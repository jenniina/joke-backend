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
exports.verifyJoke = exports.deleteUserFromJoke = exports.getJokesByUserAndSafe = exports.getJokesByUserAndType = exports.getJokesByUserAndCategory = exports.getJokesByUserId = exports.findJokeByJokeIdLanguageCategoryType = exports.updateJoke = exports.addJoke = exports.getJokes = void 0;
const types_1 = require("../../types");
const joke_1 = require("../../models/joke");
const email_1 = require("../email");
const user_1 = require("../../models/user");
var ELanguage;
(function (ELanguage) {
    ELanguage["en"] = "en";
    ELanguage["es"] = "es";
    ELanguage["fr"] = "fr";
    ELanguage["de"] = "de";
    ELanguage["pt"] = "pt";
    ELanguage["cs"] = "cs";
    ELanguage["fi"] = "fi";
})(ELanguage || (ELanguage = {}));
var EError;
(function (EError) {
    EError["en"] = "An error occurred";
    EError["es"] = "Ha ocurrido un error";
    EError["fr"] = "Une erreur est survenue";
    EError["de"] = "Ein Fehler ist aufgetreten";
    EError["pt"] = "Ocorreu um erro";
    EError["cs"] = "Do\u0161lo k chyb\u011B";
    EError["fi"] = "Tapahtui virhe";
})(EError || (EError = {}));
var EAnErrorOccurredAddingTheJoke;
(function (EAnErrorOccurredAddingTheJoke) {
    EAnErrorOccurredAddingTheJoke["en"] = "An error occurred adding the joke";
    EAnErrorOccurredAddingTheJoke["es"] = "Ha ocurrido un error al agregar la broma";
    EAnErrorOccurredAddingTheJoke["fr"] = "Une erreur s'est produite lors de l'ajout de la blague";
    EAnErrorOccurredAddingTheJoke["de"] = "Beim Hinzuf\u00FCgen des Witzes ist ein Fehler aufgetreten";
    EAnErrorOccurredAddingTheJoke["pt"] = "Ocorreu um erro ao adicionar a piada";
    EAnErrorOccurredAddingTheJoke["cs"] = "P\u0159i p\u0159id\u00E1v\u00E1n\u00ED vtipu do\u0161lo k chyb\u011B";
    EAnErrorOccurredAddingTheJoke["fi"] = "Vitsi\u00E4 lis\u00E4tt\u00E4ess\u00E4 tapahtui virhe";
})(EAnErrorOccurredAddingTheJoke || (EAnErrorOccurredAddingTheJoke = {}));
var EJokeAdded;
(function (EJokeAdded) {
    EJokeAdded["en"] = "Joke added";
    EJokeAdded["es"] = "Broma agregada";
    EJokeAdded["fr"] = "Blague ajout\u00E9e";
    EJokeAdded["de"] = "Witz hinzugef\u00FCgt";
    EJokeAdded["pt"] = "Piada adicionada";
    EJokeAdded["cs"] = "Vtip p\u0159id\u00E1n";
    EJokeAdded["fi"] = "Vitsi lis\u00E4tty";
})(EJokeAdded || (EJokeAdded = {}));
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
    var _a, _b, _c, _d;
    return Object.assign({ jokeId: doc.jokeId, type: doc.type, category: doc.category, subCategories: doc.subCategories, language: doc.language, safe: doc.safe, flags: doc.flags, user: doc.user, private: (_a = doc.private) !== null && _a !== void 0 ? _a : undefined, verified: (_b = doc.verified) !== null && _b !== void 0 ? _b : undefined, anonymous: (_c = doc.anonymous) !== null && _c !== void 0 ? _c : undefined, author: (_d = doc.author) !== null && _d !== void 0 ? _d : undefined, createdAt: doc.createdAt, updatedAt: doc.updatedAt }, (doc.type === types_1.EJokeType.single
        ? { joke: doc.joke }
        : { setup: doc.setup, delivery: doc.delivery }));
};
const addJoke = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j;
    //Joke.collection.dropIndex('_id')
    try {
        const body = req.body;
        // let joke: IJoke
        // // Check if a joke already exists
        // const existingJoke = await (body &&
        //   Joke.findOne({
        //     jokeId: body.jokeId,
        //     type: body.type,
        //     category: body.category,
        //     language: body.language,
        //   }))
        // if (existingJoke) {
        //   // Check if the user ID already exists in the user array
        //   if (!existingJoke.user.includes(req.body.user)) {
        //     existingJoke.user.push(req.body.user[0])
        //     await existingJoke.save()
        //   }
        //   joke = mapToJoke(existingJoke)
        // } else {
        //   if (req.body.type === EJokeType.single) {
        //     const savedJoke = await new Joke({
        //       jokeId: body.jokeId,
        //       joke: req.body.joke,
        //       category: body.category,
        //       type: body.type,
        //       safe: req.body.safe,
        //       user: body.user,
        //       language: body.language,
        //     }).save()
        //     joke = mapToJoke(savedJoke)
        //   } else {
        //     const savedJoke = await new Joke({
        //       jokeId: body.jokeId,
        //       setup: req.body.setup,
        //       delivery: req.body.delivery,
        //       category: body.category,
        //       type: body.type,
        //       safe: req.body.safe,
        //       user: body.user,
        //       language: body.language,
        //     }).save()
        //     joke = mapToJoke(savedJoke)
        //   }
        // }
        const filter = {
            jokeId: body.jokeId.toString(),
            type: body.type,
            category: body.category,
            language: body.language,
        };
        const update = req.body.type === types_1.EJokeType.single
            ? {
                $setOnInsert: {
                    jokeId: body.jokeId.toString(),
                    joke: req.body.joke,
                    category: body.category,
                    subCategories: body.subCategories,
                    type: body.type,
                    safe: req.body.safe,
                    flags: req.body.flags,
                    private: (_a = req.body.private) !== null && _a !== void 0 ? _a : undefined,
                    verified: (_b = req.body.verified) !== null && _b !== void 0 ? _b : undefined,
                    anonymous: (_c = req.body.anonymous) !== null && _c !== void 0 ? _c : undefined,
                    author: (_d = req.body.author) !== null && _d !== void 0 ? _d : undefined,
                    language: body.language,
                },
                $addToSet: { user: { $each: body.user } },
            }
            : {
                $setOnInsert: {
                    jokeId: body.jokeId.toString(),
                    setup: req.body.setup,
                    delivery: req.body.delivery,
                    category: body.category,
                    subCategories: body.subCategories,
                    type: body.type,
                    safe: req.body.safe,
                    flags: req.body.flags,
                    private: (_e = req.body.private) !== null && _e !== void 0 ? _e : undefined,
                    verified: (_f = req.body.verified) !== null && _f !== void 0 ? _f : undefined,
                    anonymous: (_g = req.body.anonymous) !== null && _g !== void 0 ? _g : undefined,
                    author: (_h = req.body.author) !== null && _h !== void 0 ? _h : undefined,
                    language: body.language,
                },
                $addToSet: { user: { $each: body.user } },
            };
        const joke = (yield joke_1.Joke.findOneAndUpdate(filter, update, {
            new: true,
            upsert: true,
        }));
        //Object.values(joke.flags).some(Boolean)
        if (joke.private === false) {
            const subject = 'A joke needs verification';
            const message = `${joke._id}, ${joke.type}, ${joke.category}, ${joke.language}, ${joke.safe}, ${Object.entries(joke.flags)
                .filter(([key, value]) => value)
                .map(([key, value]) => key)
                .join(', ')}, ${joke.user}, ${joke.type === types_1.EJokeType.twopart && joke.setup ? joke.setup : ''}, ${joke.type === types_1.EJokeType.twopart && joke.delivery ? joke.delivery : ''}, ${joke.type === types_1.EJokeType.single && joke.joke ? joke.joke : ''}`;
            const adminEmail = process.env.NODEMAILER_USER || '';
            const link = `${process.env.BASE_URI}/api/jokes/${joke._id}/verification`;
            const language = (_j = joke.language) !== null && _j !== void 0 ? _j : 'en';
            (0, email_1.sendMail)(subject, message, adminEmail, language, link)
                .then((response) => {
                console.log(email_1.EEmailSent[joke.language], response);
                res.status(201).json({
                    success: true,
                    message: types_1.EEmailSentToAdministratorPleaseWaitForApproval[joke.language],
                    joke,
                });
            })
                .catch((error) => {
                console.error(email_1.EErrorSendingMail[joke.language], error);
                res.status(500).json({
                    success: false,
                    message: email_1.EErrorSendingMail[joke.language],
                });
            });
        }
        // const existingJoke = await Joke.findOne(filter)
        // let joke
        // if (existingJoke) {
        //   // If the joke exists, update the user array
        //   existingJoke.user = [...new Set([...existingJoke.user, ...body.user])]
        //   joke = await existingJoke.save()
        // } else {
        //   // If the joke doesn't exist, create a new joke
        //   const jokeData =
        //     req.body.type === EJokeType.single
        //       ? {
        //           jokeId: body.jokeId,
        //           joke: req.body.joke,
        //           category: body.category,
        //           type: body.type,
        //           safe: req.body.safe,
        //           user: body.user,
        //           language: body.language,
        //         }
        //       : {
        //           jokeId: body.jokeId,
        //           setup: req.body.setup,
        //           delivery: req.body.delivery,
        //           category: body.category,
        //           type: body.type,
        //           safe: req.body.safe,
        //           user: body.user,
        //           language: body.language,
        //         }
        //   joke = await new Joke(jokeData).save()
        // }
        res
            .status(201)
            .json({ success: true, message: EJokeAdded[joke.language], joke });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({
            success: false,
            message: EAnErrorOccurredAddingTheJoke[req.body.language] ||
                'An error occurred adding the joke',
        });
    }
});
exports.addJoke = addJoke;
const verifyJoke = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _k;
    let EYourJokeHasBeenVerified;
    (function (EYourJokeHasBeenVerified) {
        EYourJokeHasBeenVerified["en"] = "Your joke has been verified";
        EYourJokeHasBeenVerified["es"] = "Tu broma ha sido verificada";
        EYourJokeHasBeenVerified["fr"] = "Votre blague a \u00E9t\u00E9 v\u00E9rifi\u00E9e";
        EYourJokeHasBeenVerified["de"] = "Dein Witz wurde \u00FCberpr\u00FCft";
        EYourJokeHasBeenVerified["pt"] = "Sua piada foi verificada";
        EYourJokeHasBeenVerified["cs"] = "V\u00E1\u0161 vtip byl ov\u011B\u0159en";
        EYourJokeHasBeenVerified["fi"] = "Vitsisi on vahvistettu";
    })(EYourJokeHasBeenVerified || (EYourJokeHasBeenVerified = {}));
    try {
        const joke = yield joke_1.Joke.findOneAndUpdate({ _id: req.params.id }, { verified: true, private: false });
        const subject = EYourJokeHasBeenVerified[joke === null || joke === void 0 ? void 0 : joke.language];
        const message = `${joke === null || joke === void 0 ? void 0 : joke.category}, ${(joke === null || joke === void 0 ? void 0 : joke.type) === types_1.EJokeType.twopart ? `${joke === null || joke === void 0 ? void 0 : joke.setup} ${joke === null || joke === void 0 ? void 0 : joke.delivery}` : ''} - ${(joke === null || joke === void 0 ? void 0 : joke.type) === types_1.EJokeType.single ? joke === null || joke === void 0 ? void 0 : joke.joke : ''}`;
        const author = (joke === null || joke === void 0 ? void 0 : joke.author) || '';
        const recipient = yield user_1.User.findOne({ _id: author });
        const username = (recipient === null || recipient === void 0 ? void 0 : recipient.username) || '';
        const link = `${process.env.SITE_URL}/portfolio/jokes?login=login`;
        const language = (_k = joke === null || joke === void 0 ? void 0 : joke.language) !== null && _k !== void 0 ? _k : 'en';
        (0, email_1.sendMail)(subject, message, username, language, link)
            .then((response) => {
            console.log(email_1.EEmailSent[joke === null || joke === void 0 ? void 0 : joke.language], response);
            res.status(201).json({
                success: true,
                message: email_1.EEmailSent[language],
                joke,
            });
            return;
        })
            .catch((error) => {
            console.error(email_1.EErrorSendingMail[joke === null || joke === void 0 ? void 0 : joke.language], error);
            res.status(500).json({
                success: false,
                message: email_1.EErrorSendingMail[joke === null || joke === void 0 ? void 0 : joke.language],
            });
        });
        //res.status(200).json({ message: 'Joke verified', joke })
    }
    catch (error) {
        res.status(500).json({
            message: `An error occurred: ${error === null || error === void 0 ? void 0 : error.message} ${error}`,
        });
        console.error('Error:', error);
    }
});
exports.verifyJoke = verifyJoke;
const updateJoke = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _l;
    try {
        const { params: { jokeId, language }, body, } = req;
        let joke;
        const findJoke = yield joke_1.Joke.findOne({ jokeId, language });
        if ((findJoke === null || findJoke === void 0 ? void 0 : findJoke.private) === true && body.private === false) {
            // const subject = 'A joke needs verification'
            // const message = `${body.jokeId}, ${body.type}, ${body.category}, ${
            //   body.language
            // }, ${body.safe}, ${Object.entries(body.flags)
            //   .filter(([key, value]) => value)
            //   .map(([key, value]) => key)
            //   .join(', ')}, ${body.user}, ${body.setup ? body.setup : ''}, ${
            //   body.delivery ? body.delivery : ''
            // }, ${body.body ? body.joke : ''}`
            // const adminEmail = process.env.NODEMAILER_USER || ''
            // const link = `${process.env.BASE_URI}/api/jokes/${body.jokeId}/verification`
            // sendMail(subject, message, adminEmail, body.language, link)
            //   .then((response) => console.log(EEmailSent[body.language as ELanguage], response))
            //   .catch((error) =>
            //     console.error(EErrorSendingMail[body.language as ELanguage], error)
            //   )
            const subject = 'A joke needs verification';
            const message = `${body.jokeId}, ${body.type}, ${body.category}, ${body.language}, ${body.safe}, ${Object.entries(body.flags)
                .filter(([key, value]) => value)
                .map(([key, value]) => key)
                .join(', ')}, ${body.user}, ${body.type === types_1.EJokeType.twopart && body.setup ? body.setup : ''}, ${body.type === types_1.EJokeType.twopart && body.delivery ? body.delivery : ''}, ${body.type === types_1.EJokeType.single && body.body ? body.body : ''}`;
            const adminEmail = process.env.NODEMAILER_USER || '';
            const link = `${process.env.BASE_URI}/api/jokes/${body.jokeId}/verification`;
            const language = (_l = body.language) !== null && _l !== void 0 ? _l : 'en';
            (0, email_1.sendMail)(subject, message, adminEmail, language, link)
                .then((response) => {
                console.log(email_1.EEmailSent[body.language], response);
                res.status(201).json({
                    success: true,
                    message: types_1.EEmailSentToAdministratorPleaseWaitForApproval[body.language],
                    joke,
                });
            })
                .catch((error) => {
                console.error(email_1.EErrorSendingMail[language], error);
                res.status(500).json({
                    success: false,
                    message: email_1.EErrorSendingMail[language],
                });
            });
            return;
        }
        else {
            const updateJoke = yield joke_1.Joke.findOneAndUpdate({ jokeId, language }, body);
            joke = mapToJoke(updateJoke);
            res
                .status(200)
                .json({ success: true, message: types_1.EJokeUpdated[language], joke });
        }
    }
    catch (error) {
        res.status(500).json({
            success: false,
            message: EError[req.params.language] || 'An error occurred',
        });
        console.error('Error:', error);
    }
});
exports.updateJoke = updateJoke;
const deleteUserFromJoke = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _m;
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
        res.status(200).json({
            message: types_1.EUserDeletedFromJoke[(_m = joke === null || joke === void 0 ? void 0 : joke.language) !== null && _m !== void 0 ? _m : 'en'],
            joke,
        });
    }
    catch (error) {
        res
            .status(500)
            .json({ message: EError[req.params.lang] || 'An error occurred' });
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
//     res.status(500).json({ message: EError[language as ELanguage] })
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
        res
            .status(500)
            .json({ message: EError[req.params.language] || 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.findJokeByJokeIdLanguageCategoryType = findJokeByJokeIdLanguageCategoryType;
// const getJokesByUsername = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const jokes: IJoke[] | null = await Joke.findOne({ user: req.params.username })
//     res.status(200).json({ jokes })
//   } catch (error) {
//     res
//       .status(500)
//       .json({ message: EError[language as ELanguage] || 'An error occurred' })
//     console.error('Error:', error)
//   }
// }
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
        res
            .status(500)
            .json({ message: EError[req.params.language] || 'An error occurred' });
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
        res
            .status(500)
            .json({ message: EError[req.params.language] || 'An error occurred' });
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
        res
            .status(500)
            .json({ message: EError[req.params.language] || 'An error occurred' });
        console.error('Error:', error);
    }
});
exports.getJokesByUserAndSafe = getJokesByUserAndSafe;
