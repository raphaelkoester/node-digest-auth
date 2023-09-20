/// <reference types="node" />
import * as http from "http";
declare class HTTPDigest {
    private nc;
    private username;
    private password;
    private shouldEnd;
    private httpRequest;
    constructor(username: string, password: string, useHttps?: boolean, shouldEnd?: boolean);
    request(options: http.RequestOptions, callback: (res: http.IncomingMessage) => void): http.ClientRequest;
    private _handleResponse;
    private _parseChallenge;
    private _compileParams;
    private updateNC;
}
export declare function createDigestClient(username: string, password: string, useHttps?: boolean, shouldEnd?: boolean): HTTPDigest;
export {};
