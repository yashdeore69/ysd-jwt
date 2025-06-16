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
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MalformedTokenError = exports.ClaimValidationError = exports.InvalidSignatureError = exports.TokenExpiredError = exports.MissingKeyError = exports.TokenError = exports.verify = exports.sign = void 0;
var sign_1 = require("./sign");
Object.defineProperty(exports, "sign", { enumerable: true, get: function () { return sign_1.sign; } });
var verify_1 = require("./verify");
Object.defineProperty(exports, "verify", { enumerable: true, get: function () { return verify_1.verify; } });
__exportStar(require("./types"), exports);
var errors_1 = require("./errors");
Object.defineProperty(exports, "TokenError", { enumerable: true, get: function () { return errors_1.TokenError; } });
Object.defineProperty(exports, "MissingKeyError", { enumerable: true, get: function () { return errors_1.MissingKeyError; } });
Object.defineProperty(exports, "TokenExpiredError", { enumerable: true, get: function () { return errors_1.TokenExpiredError; } });
Object.defineProperty(exports, "InvalidSignatureError", { enumerable: true, get: function () { return errors_1.InvalidSignatureError; } });
Object.defineProperty(exports, "ClaimValidationError", { enumerable: true, get: function () { return errors_1.ClaimValidationError; } });
Object.defineProperty(exports, "MalformedTokenError", { enumerable: true, get: function () { return errors_1.MalformedTokenError; } });
