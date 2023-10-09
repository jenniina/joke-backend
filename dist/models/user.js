"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.User = void 0;
const mongoose_1 = require("mongoose");
const userSchema = new mongoose_1.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        minlength: 3,
    },
    name: {
        type: String,
        required: false,
        minlength: 2,
    },
    password: {
        type: String,
        required: true,
        minlength: 3,
    },
    language: {
        type: String,
        required: false,
        minlength: 2,
    },
    verified: {
        type: Boolean,
        required: true,
        default: false,
    },
}, { timestamps: true });
exports.User = (0, mongoose_1.model)('User', userSchema);
