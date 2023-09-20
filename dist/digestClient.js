"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDigestClient = void 0;
const crypto = __importStar(require("crypto"));
const http = __importStar(require("http"));
const https = __importStar(require("https"));
class HTTPDigest {
    constructor(username, password, useHttps = false, shouldEnd = false) {
        this.nc = 0;
        this.username = username;
        this.password = password;
        this.shouldEnd = shouldEnd;
        this.httpRequest = useHttps ? https : http;
    }
    request(options, callback) {
        if (this.shouldEnd) {
            console.log("DEVERIA ACABAR");
            return this.httpRequest
                .request(options, (res) => {
                this._handleResponse(options, res, callback);
            })
                .end();
        }
        else {
            console.log("NAO DEVERIA ACABAR");
            return this.httpRequest.request(options, (res) => {
                this._handleResponse(options, res, callback);
            });
        }
    }
    _handleResponse(options, res, callback) {
        const challenge = this._parseChallenge(res.headers["www-authenticate"]);
        const ha1 = crypto.createHash("md5");
        ha1.update([this.username, challenge.realm, this.password].join(":"));
        const ha2 = crypto.createHash("md5");
        ha2.update([options.method, options.path].join(":"));
        let cnonce = false;
        let nc = false;
        if (typeof challenge.qop === "string") {
            const cnonceHash = crypto.createHash("md5");
            cnonceHash.update(Math.random().toString(36));
            cnonce = cnonceHash.digest("hex").substr(0, 8);
            nc = this.updateNC();
        }
        const response = crypto.createHash("md5");
        const responseParams = [ha1.digest("hex"), challenge.nonce];
        if (cnonce && typeof nc === "string") {
            responseParams.push(nc);
            responseParams.push(cnonce);
        }
        responseParams.push(challenge.qop);
        responseParams.push(ha2.digest("hex"));
        response.update(responseParams.join(":"));
        const authParams = {
            username: this.username,
            realm: challenge.realm,
            nonce: challenge.nonce,
            uri: options.path,
            qop: challenge.qop,
            response: response.digest("hex"),
            opaque: challenge.opaque,
        };
        if (cnonce && typeof nc === "string") {
            authParams.nc = nc;
            authParams.cnonce = cnonce;
        }
        options.headers = Object.assign(Object.assign({}, options.headers), { Authorization: this._compileParams(authParams) });
        if (this.shouldEnd) {
            return http.request(options, callback).end();
        }
        else {
            return http.request(options, callback);
        }
    }
    _parseChallenge(digest) {
        const prefix = "Digest ";
        const challengeStr = digest.substr(digest.indexOf(prefix) + prefix.length);
        const parts = challengeStr.split(",");
        const challenge = {};
        for (const part of parts) {
            const matches = part.match(/^\s*?([a-zA-Z0-0]+)="(.*)"\s*?$/);
            if (matches && matches.length > 2) {
                challenge[matches[1]] = matches[2];
            }
        }
        return challenge;
    }
    _compileParams(params) {
        const parts = [];
        for (const key in params) {
            parts.push(`${key}="${params[key]}"`);
        }
        return "Digest " + parts.join(",");
    }
    updateNC() {
        const max = 99999999;
        this.nc++;
        if (this.nc > max) {
            this.nc = 1;
        }
        const padding = new Array(8).join("0") + "";
        const nc = this.nc + "";
        return padding.substr(0, 8 - nc.length) + nc;
    }
}
function createDigestClient(username, password, useHttps, shouldEnd) {
    return new HTTPDigest(username, password, useHttps, shouldEnd);
}
exports.createDigestClient = createDigestClient;
