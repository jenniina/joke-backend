"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.removeOldestDuplicate = exports.addQuiz = exports.getUserQuiz = exports.getQuizzes = void 0;
const quiz_1 = require("../../models/quiz");
const getQuizzes = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const quizzes = yield quiz_1.Quiz.find();
        res.status(200).json({ quizzes });
    }
    catch (error) {
        throw error;
    }
});
exports.getQuizzes = getQuizzes;
const getUserQuiz = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { id } = req.params;
        const quiz = yield quiz_1.Quiz.findOne({ user: id });
        res.status(200).json(quiz);
    }
    catch (error) {
        throw error;
    }
});
exports.getUserQuiz = getUserQuiz;
// const addQuiz = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const body = req.body as Pick<IQuiz, 'highscores' | 'user'>
//     const existingQuiz = (await Quiz.findOne({
//       user: body.user,
//     })) as IQuiz
//     if (!existingQuiz) {
//       const quiz = new Quiz({
//         highscores: body.highscores,
//         user: body.user,
//       }) as IQuiz
//       const newQuiz: IQuiz = await quiz.save()
//       res.status(201).json({ message: 'Quiz added', quiz: newQuiz })
//     } else if (!body.user) {
//       res.status(400).json({ message: 'type and user fields are required' })
//     } else {
//       existingQuiz.highscores = body.highscores
//       existingQuiz.user = body.user
//       try {
//         const updatedQuiz: IQuiz = await existingQuiz.save()
//         res.status(200).json({ message: 'Quiz updated', quiz: updatedQuiz })
//       } catch (validationError) {
//         console.error(validationError)
//         res.status(400).json({ message: 'Quiz not updated', error: validationError })
//       }
//     }
//   } catch (error) {
//     throw error
//   }
// }
const addQuiz = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const body = req.body;
        if (!body.user) {
            res.status(400).json({ message: 'user field is required' });
            return;
        }
        const existingQuiz = yield quiz_1.Quiz.findOne({
            user: body.user,
        });
        if (!existingQuiz) {
            const quiz = new quiz_1.Quiz({
                highscores: body.highscores,
                user: body.user,
            });
            const newQuiz = yield quiz.save();
            res.status(201).json({ message: 'Quiz added', quiz: newQuiz });
        }
        else {
            existingQuiz.highscores = body.highscores;
            try {
                const updatedQuiz = (yield existingQuiz.save());
                res.status(200).json({ message: 'Quiz updated', quiz: updatedQuiz });
            }
            catch (validationError) {
                console.error(validationError);
                res.status(400).json({ message: 'Quiz not updated', error: validationError });
            }
        }
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.addQuiz = addQuiz;
const removeOldestDuplicate = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { user } = req.params;
        if (!user) {
            res.status(400).json({ message: 'user field is required' });
            return;
        }
        const existingQuiz = yield quiz_1.Quiz.find({
            user: user,
        }).sort({ createdAt: 1 });
        if (existingQuiz.length > 1) {
            const oldestQuiz = existingQuiz[0];
            yield quiz_1.Quiz.deleteOne({ _id: oldestQuiz._id });
            res.status(200).json({ message: 'Quiz deleted', quiz: oldestQuiz });
        }
        else {
            res.status(200).json({ message: 'No duplicate found' });
        }
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.removeOldestDuplicate = removeOldestDuplicate;
