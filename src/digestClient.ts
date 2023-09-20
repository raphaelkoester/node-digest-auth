import * as crypto from "crypto";
import * as http from "http";
import * as https from "https";

interface Challenge {
	realm?: string;
	nonce?: string;
	qop?: string;
	opaque?: string;
	[key: string]: string | undefined;
}

interface AuthParams extends Challenge {
	username: string;
	uri: string;
	response: string;
	nc?: string;
	cnonce?: string;
}

class HTTPDigest {
	private nc: number;
	private username: string;
	private password: string;
	private shouldEnd: boolean;
	private httpRequest: typeof http | typeof https;

	constructor(
		username: string,
		password: string,
		useHttps: boolean = false,
		shouldEnd: boolean = false,
	) {
		this.nc = 0;
		this.username = username;
		this.password = password;
		this.shouldEnd = shouldEnd;
		this.httpRequest = useHttps ? https : http;
	}

	public request(
		options: http.RequestOptions,
		callback: (res: http.IncomingMessage) => void,
	) {
		if (this.shouldEnd) {
			return this.httpRequest
				.request(options, (res) => {
					this._handleResponse(options, res, callback);
				})
				.end();
		} else {
			return this.httpRequest.request(options, (res) => {
				this._handleResponse(options, res, callback);
			});
		}
	}

	private _handleResponse(
		options: http.RequestOptions,
		res: http.IncomingMessage,
		callback: (res: http.IncomingMessage) => void,
	) {
		const challenge: Challenge = this._parseChallenge(
			res.headers["www-authenticate"] as string,
		);

		const ha1 = crypto.createHash("md5");
		ha1.update([this.username, challenge.realm, this.password].join(":"));

		const ha2 = crypto.createHash("md5");
		ha2.update([options.method, options.path].join(":"));

		let cnonce: string | false = false;
		let nc: string | false = false;

		if (typeof challenge.qop === "string") {
			const cnonceHash = crypto.createHash("md5");
			cnonceHash.update(Math.random().toString(36));
			cnonce = cnonceHash.digest("hex").substr(0, 8);
			nc = this._updateNC();
		}

		const response = crypto.createHash("md5");
		const responseParams: string[] = [ha1.digest("hex"), challenge.nonce!];

		if (cnonce && typeof nc === "string") {
			responseParams.push(nc!);
			responseParams.push(cnonce);
		}

		responseParams.push(challenge.qop!);
		responseParams.push(ha2.digest("hex"));
		response.update(responseParams.join(":"));

		const authParams: AuthParams = {
			username: this.username,
			realm: challenge.realm!,
			nonce: challenge.nonce!,
			uri: options.path!,
			qop: challenge.qop!,
			response: response.digest("hex"),
			opaque: challenge.opaque!,
		};

		if (cnonce && typeof nc === "string") {
			authParams.nc = nc;
			authParams.cnonce = cnonce;
		}

		options.headers = {
			...options.headers,
			Authorization: this._compileParams(authParams),
		};

		if (this.shouldEnd) {
			return http.request(options, callback).end();
		} else {
			return http.request(options, callback);
		}
	}

	private _parseChallenge(digest: string): Challenge {
		const prefix = "Digest ";
		const challengeStr = digest.substr(
			digest.indexOf(prefix) + prefix.length,
		);
		const parts = challengeStr.split(",");
		const challenge: Challenge = {};

		for (const part of parts) {
			const matches = part.match(/^\s*?([a-zA-Z0-0]+)="(.*)"\s*?$/);
			if (matches && matches.length > 2) {
				challenge[matches[1]] = matches[2];
			}
		}

		return challenge;
	}

	private _compileParams(params: AuthParams): string {
		const parts = [];
		for (const key in params) {
			parts.push(`${key}="${params[key]}"`);
		}
		return "Digest " + parts.join(",");
	}

	private _updateNC(): string {
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

export function createDigestClient(
	username: string,
	password: string,
	useHttps?: boolean,
	shouldEnd?: boolean,
): HTTPDigest {
	return new HTTPDigest(username, password, useHttps, shouldEnd);
}
