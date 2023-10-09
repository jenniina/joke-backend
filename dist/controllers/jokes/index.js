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
exports.deleteUserFromJoke = exports.getJokesByUserAndSafe = exports.getJokesByUserAndType = exports.getJokesByUserAndCategory = exports.getJokesByUserId = exports.getJokesByUsername = exports.findJokeByJokeIdLanguageCategoryType = exports.updateJoke = exports.addJoke = exports.getJokes = void 0;
const types_1 = require("../../types");
const joke_1 = require("../../models/joke");
const getJokes = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const jokes = yield joke_1.Joke.find();
        res.status(200).json(jokes);
    }
    catch (error) {
        res.status(500).json({ message: 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.getJokes = getJokes;
const mapToJoke = (doc) => {
    return Object.assign({ jokeId: doc.jokeId, type: doc.type, category: doc.category, language: doc.language, safe: doc.safe, user: doc.user, createdAt: doc.createdAt, updatedAt: doc.updatedAt }, (doc.type === types_1.EJokeType.single
        ? { joke: doc.joke }
        : { setup: doc.setup, delivery: doc.delivery }));
};
const addJoke = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    //Joke.collection.dropIndex('jokeId_1')
    try {
        const body = req.body;
        // Validate input fields
        if (!body.jokeId || !body.category || !body.user || !body.language) {
            res.status(400).json({ message: 'Missing required fields' });
        }
        let joke;
        // Check if a joke already exists
        const existingJoke = yield (body &&
            joke_1.Joke.findOne({
                jokeId: body.jokeId,
                type: body.type,
                category: body.category,
                language: body.language,
            }));
        if (existingJoke) {
            // Check if the user ID already exists in the user array
            if (!existingJoke.user.includes(req.body.user)) {
                existingJoke.user.push(req.body.user);
                yield existingJoke.save();
            }
            joke = mapToJoke(existingJoke);
        }
        else {
            if (req.body.type === types_1.EJokeType.single) {
                const savedJoke = yield new joke_1.Joke({
                    jokeId: body.jokeId,
                    joke: req.body.joke,
                    category: body.category,
                    type: body.type,
                    safe: req.body.safe,
                    user: [body.user],
                    language: body.language,
                }).save();
                joke = mapToJoke(savedJoke);
            }
            else {
                const savedJoke = yield new joke_1.Joke({
                    jokeId: body.jokeId,
                    setup: req.body.setup,
                    delivery: req.body.delivery,
                    category: body.category,
                    type: body.type,
                    safe: req.body.safe,
                    user: [body.user],
                    language: body.language,
                }).save();
                joke = mapToJoke(savedJoke);
            }
        }
        res.status(201).json({ success: true, message: 'Joke added', data: joke });
    }
    catch (error) {
        res.status(500).json({ success: false, message: 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.addJoke = addJoke;
const updateJoke = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { params: { jokeId }, body, } = req;
        let joke;
        const updateJoke = yield joke_1.Joke.findOneAndUpdate({ jokeId: jokeId }, body);
        joke = mapToJoke(updateJoke);
        const allJokes = yield joke_1.Joke.find();
        res.status(200).json({ message: 'Joke updated', joke, jokes: allJokes });
    }
    catch (error) {
        res.status(500).json({ message: 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.updateJoke = updateJoke;
const deleteUserFromJoke = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { params: { id: _id, userId }, } = req;
        const joke = yield joke_1.Joke.findOne({ _id: _id });
        const userIndex = joke === null || joke === void 0 ? void 0 : joke.user.indexOf(userId);
        if (userIndex !== undefined && userIndex !== -1) {
            joke === null || joke === void 0 ? void 0 : joke.user.splice(userIndex, 1);
            yield joke.save();
        }
        if ((joke === null || joke === void 0 ? void 0 : joke.user.length) === 0) {
            yield joke_1.Joke.findOneAndDelete({ _id: _id });
        }
        res.status(200).json({ message: 'User deleted from joke', joke });
    }
    catch (error) {
        res.status(500).json({ message: 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.deleteUserFromJoke = deleteUserFromJoke;
// const deleteUserFromJokeAndDeleteJokeIfUserArrayEmpty = async (
//   req: Request,
//   res: Response
// ): Promise<void> => {
//   try {
//     const {
//       params: { id: _id, userId },
//     } = req
//     const joke: IJoke | null = await Joke.findOne({ _id: _id })
//     const userIndex = joke?.user.indexOf(userId)
//     if (userIndex !== undefined && userIndex !== -1) {
//       joke?.user.splice(userIndex, 1)
//       await joke?.save()
//     }
//     res.status(200).json({ message: 'User deleted from joke', joke })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }
const findJokeByJokeIdLanguageCategoryType = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const joke = yield joke_1.Joke.findOne({
            jokeId: req.params.jokeId,
            category: req.params.category,
            language: req.params.language,
            type: req.params.type,
        });
        res.status(200).json(joke);
    }
    catch (error) {
        res.status(500).json({ message: 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.findJokeByJokeIdLanguageCategoryType = findJokeByJokeIdLanguageCategoryType;
const getJokesByUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const jokes = yield joke_1.Joke.findOne({ user: req.params.username });
        res.status(200).json({ jokes });
    }
    catch (error) {
        res.status(500).json({ message: 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.getJokesByUsername = getJokesByUsername;
const getJokesByUserId = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const jokes = yield joke_1.Joke.findOne({ user: req.params.id });
        res.status(200).json({ jokes });
    }
    catch (error) {
        throw error;
    }
});
exports.getJokesByUserId = getJokesByUserId;
const getJokesByUserAndCategory = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const jokes = yield joke_1.Joke.findOne({
            user: req.params.id,
            category: req.params.category,
        });
        res.status(200).json({ jokes });
    }
    catch (error) {
        res.status(500).json({ message: 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.getJokesByUserAndCategory = getJokesByUserAndCategory;
const getJokesByUserAndType = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const jokes = yield joke_1.Joke.findOne({
            user: req.params.id,
            type: req.params.type,
        });
        res.status(200).json({ jokes });
    }
    catch (error) {
        res.status(500).json({ message: 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.getJokesByUserAndType = getJokesByUserAndType;
const getJokesByUserAndSafe = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const jokes = yield joke_1.Joke.findOne({
            user: req.params.id,
            safe: req.params.safe,
        });
        res.status(200).json({ jokes });
    }
    catch (error) {
        res.status(500).json({ message: 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.getJokesByUserAndSafe = getJokesByUserAndSafe;
