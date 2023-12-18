"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Todo = void 0;
const mongoose_1 = require("mongoose");
const taskSchema = new mongoose_1.Schema({
    key: {
        type: String,
        required: true,
    },
    name: {
        type: String,
        required: true,
    },
    complete: {
        type: Boolean,
        required: true,
    },
}, { timestamps: true });
const todoSchema = new mongoose_1.Schema({
    user: {
        type: mongoose_1.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    todos: {
        type: [taskSchema],
        default: [],
    },
}, { timestamps: true });
exports.Todo = (0, mongoose_1.model)('Todo', todoSchema);
