"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Quiz = void 0;
const mongoose_1 = require("mongoose");
const quizSchema = new mongoose_1.Schema({
    highscores: {
        easy: {
            score: { type: Number, default: 0 },
            time: { type: Number, default: 210 },
        },
        medium: {
            score: { type: Number, default: 0 },
            time: { type: Number, default: 210 },
        },
        hard: {
            score: { type: Number, default: 0 },
            time: { type: Number, default: 210 },
        },
    },
    user: {
        type: mongoose_1.Schema.Types.ObjectId,
        ref: 'User',
    },
}, { timestamps: true });
exports.Quiz = (0, mongoose_1.model)('Quiz', quizSchema);
