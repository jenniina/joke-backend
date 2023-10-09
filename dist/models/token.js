"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Token = void 0;
const mongoose_1 = require("mongoose");
const tokenSchema = new mongoose_1.Schema({
    token: {
        type: String,
        required: true,
        unique: true,
    },
    createdAt: {
        type: Date,
        expires: 3600,
        default: Date.now,
    },
}, { timestamps: true });
exports.Token = (0, mongoose_1.model)('Token', tokenSchema);
