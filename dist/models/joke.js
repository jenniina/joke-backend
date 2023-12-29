"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Joke = void 0;
const mongoose_1 = require("mongoose");
const jokeSchema = new mongoose_1.Schema({
    jokeId: {
        type: String,
        required: true,
        unique: false,
    },
    type: {
        type: String,
        required: true,
        enum: ['single', 'twopart'],
    },
    category: {
        type: String,
        required: true,
        // enum: ['Any', 'Misc', 'Programming', 'Dark', 'Pun', 'Spooky', 'Christmas'],
    },
    language: {
        type: String,
        required: true,
        enum: ['en', 'es', 'fr', 'de', 'pt', 'cs'],
    },
    safe: {
        type: Boolean,
        required: true,
    },
    user: [
        {
            type: mongoose_1.Schema.Types.ObjectId,
            required: true,
            ref: 'User',
        },
    ],
    setup: {
        type: String,
    },
    delivery: {
        type: String,
    },
    joke: {
        type: String,
    },
}, { timestamps: true });
exports.Joke = (0, mongoose_1.model)('Joke', jokeSchema);
