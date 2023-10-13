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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.refreshExpiredToken = exports.requestNewToken = exports.findUserByUsername = exports.verifyToken = exports.verifyTokenMiddleware = exports.generateToken = exports.changeUsernameToken = exports.changeUsername = exports.resetUsernameToken = exports.resetUsername = exports.forgotUsername = exports.verifyUsernameToken = exports.verifyUsername = exports.changeEmailToken = exports.changeEmail = exports.verifyEmailToken = exports.verifyEmail = exports.changePasswordToken = exports.changePassword = exports.resetPasswordToken = exports.resetPassword = exports.forgotPassword = exports.checkSession = exports.logoutUser = exports.registerUser = exports.loginUser = exports.deleteUser = exports.updateUser = exports.addUser = exports.getUser = exports.getUsers = exports.authenticateUser = exports.checkIfAdmin = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const user_1 = require("../../models/user");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dotenv = require('dotenv');
dotenv.config();
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
    host: `${process.env.EMAIL_SERVICE}`,
    port: `${process.env.EMAIL_PORT}`,
    secure: false,
    auth: {
        user: `${process.env.EMAIL_USER}`,
        pass: `${process.env.EMAIL_PASSWORD}`,
    },
});
var EError;
(function (EError) {
    EError["en"] = "An error occurred";
    EError["es"] = "Ha ocurrido un error";
    EError["fr"] = "Une erreur est survenue";
    EError["de"] = "Ein Fehler ist aufgetreten";
    EError["pt"] = "Ocorreu um erro";
    EError["cs"] = "Do\u0161lo k chyb\u011B";
})(EError || (EError = {}));
var ELanguage;
(function (ELanguage) {
    ELanguage["en"] = "en";
    ELanguage["es"] = "es";
    ELanguage["fr"] = "fr";
    ELanguage["de"] = "de";
    ELanguage["pt"] = "pt";
    ELanguage["cs"] = "cs";
})(ELanguage || (ELanguage = {}));
var ETheComediansCompanion;
(function (ETheComediansCompanion) {
    ETheComediansCompanion["en"] = "The Comedian's Companion";
    ETheComediansCompanion["es"] = "El Compa\u00F1ero del Comediante";
    ETheComediansCompanion["fr"] = "Le Compagnon du Com\u00E9dien";
    ETheComediansCompanion["de"] = "Der Begleiter des Komikers";
    ETheComediansCompanion["pt"] = "O Companheiro do Comediante";
    ETheComediansCompanion["cs"] = "Spole\u010Dn\u00EDk komika";
})(ETheComediansCompanion || (ETheComediansCompanion = {}));
var EBackToTheApp;
(function (EBackToTheApp) {
    EBackToTheApp["en"] = "Back to the App";
    EBackToTheApp["es"] = "Volver a la aplicaci\u00F3n";
    EBackToTheApp["fr"] = "Retour \u00E0 l application";
    EBackToTheApp["de"] = "Zur\u00FCck zur App";
    EBackToTheApp["pt"] = "Voltar para o aplicativo";
    EBackToTheApp["cs"] = "Zp\u011Bt do aplikace";
})(EBackToTheApp || (EBackToTheApp = {}));
var EErrorCreatingToken;
(function (EErrorCreatingToken) {
    EErrorCreatingToken["en"] = "Error creating token";
    EErrorCreatingToken["es"] = "Error al crear el token";
    EErrorCreatingToken["fr"] = "Erreur lors de la cr\u00E9ation du jeton";
    EErrorCreatingToken["de"] = "Fehler beim Erstellen des Tokens";
    EErrorCreatingToken["pt"] = "Erro ao criar token";
    EErrorCreatingToken["cs"] = "Chyba p\u0159i vytv\u00E1\u0159en\u00ED tokenu";
})(EErrorCreatingToken || (EErrorCreatingToken = {}));
var EHelloWelcome;
(function (EHelloWelcome) {
    EHelloWelcome["en"] = "Hello, welcome to the Comedian's Companion";
    EHelloWelcome["es"] = "Hola, bienvenido al Compa\u00F1ero del Comediante";
    EHelloWelcome["fr"] = "Bonjour, bienvenue au Compagnon du Com\u00E9dien";
    EHelloWelcome["de"] = "Hallo, willkommen beim Begleiter des Komikers";
    EHelloWelcome["pt"] = "Ol\u00E1, bem-vindo ao Companheiro do Comediante";
    EHelloWelcome["cs"] = "Ahoj, v\u00EDtejte u Spole\u010Dn\u00EDka komika";
})(EHelloWelcome || (EHelloWelcome = {}));
var EEmailMessage;
(function (EEmailMessage) {
    EEmailMessage["en"] = "Please verify your email";
    EEmailMessage["es"] = "Por favor verifica tu correo electr\u00F3nico";
    EEmailMessage["fr"] = "Veuillez v\u00E9rifier votre email";
    EEmailMessage["de"] = "Bitte \u00FCberpr\u00FCfen Sie Ihre E-Mail";
    EEmailMessage["pt"] = "Por favor, verifique seu email";
    EEmailMessage["cs"] = "Pros\u00EDm, ov\u011B\u0159te sv\u016Fj email";
})(EEmailMessage || (EEmailMessage = {}));
var EErrorSendingMail;
(function (EErrorSendingMail) {
    EErrorSendingMail["en"] = "Error sending mail";
    EErrorSendingMail["es"] = "Error al enviar el correo";
    EErrorSendingMail["fr"] = "Erreur lors de l envoi du mail";
    EErrorSendingMail["de"] = "Fehler beim Senden der E-Mail";
    EErrorSendingMail["pt"] = "Erro ao enviar email";
    EErrorSendingMail["cs"] = "Chyba p\u0159i odes\u00EDl\u00E1n\u00ED emailu";
})(EErrorSendingMail || (EErrorSendingMail = {}));
var ETokenSent;
(function (ETokenSent) {
    ETokenSent["en"] = "Token sent";
    ETokenSent["es"] = "Token enviado";
    ETokenSent["fr"] = "Jeton envoy\u00E9";
    ETokenSent["de"] = "Token gesendet";
    ETokenSent["pt"] = "Token enviado";
    ETokenSent["cs"] = "Token odesl\u00E1n";
})(ETokenSent || (ETokenSent = {}));
const generateToken = (userId) => {
    if (!userId)
        return undefined;
    const payload = { userId };
    const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf';
    const options = { expiresIn: '1d' };
    return jsonwebtoken_1.default.sign(payload, secret, options);
};
exports.generateToken = generateToken;
// const verifyToken = (token: string): ITokenPayload => {
//   const secret: Secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
//   return jwt.verify(token, secret) as ITokenPayload
// }
const verifyToken = (token) => {
    const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf';
    try {
        if (token)
            return jsonwebtoken_1.default.verify(token, secret);
        else
            return undefined;
    }
    catch (error) {
        if (error.name === 'TokenExpiredError') {
            throw new Error('Token expired');
        }
        else {
            throw error; // Re-throw other errors
        }
    }
};
exports.verifyToken = verifyToken;
const verifyTokenMiddleware = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const token = (_a = req.headers.authorization) === null || _a === void 0 ? void 0 : _a.split(' ')[1];
        if (!token)
            throw new Error('No token provided');
        const decoded = verifyToken(token);
        const user = yield user_1.User.findById(decoded === null || decoded === void 0 ? void 0 : decoded.userId);
        if (!user)
            throw new Error('User not found');
        res.status(200).json({ message: 'Token verified' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.verifyTokenMiddleware = verifyTokenMiddleware;
// Middleware to check if the user has admin role
const checkIfAdmin = (req, res, next) => {
    const user = req.body;
    if (user && user.role > 2) {
        // User is an admin, allow access
        next();
    }
    else {
        // User is not an admin, deny access
        res.status(403).json({ message: 'Access denied. Admin privilege required.' });
    }
};
exports.checkIfAdmin = checkIfAdmin;
const authenticateUser = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    try {
        const token = (_b = req.headers.authorization) === null || _b === void 0 ? void 0 : _b.split(' ')[1];
        if (!token)
            throw new Error('No token provided');
        const decoded = verifyToken(token);
        const user = yield user_1.User.findById(decoded === null || decoded === void 0 ? void 0 : decoded.userId);
        if (!user)
            throw new Error('User not authenticated');
        // Attach user information to the request object
        req.body = user;
        next();
    }
    catch (error) {
        console.error('Error:', error);
        res.status(401).json({ message: 'Authentication failed' });
    }
});
exports.authenticateUser = authenticateUser;
const getUsers = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const users = yield user_1.User.find();
        res.status(200).json({ users });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.getUsers = getUsers;
const getUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const user = yield user_1.User.findById(req.params.id);
        res.status(200).json(user);
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.getUser = getUser;
const addUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const body = req.body;
        const user = new user_1.User({
            username: body.username,
            password: body.password,
            language: body.language,
            verified: false,
        });
        const newUser = yield user.save();
        const allUsers = yield user_1.User.find();
        res.status(201).json({ message: 'User added', user: newUser, users: allUsers });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.addUser = addUser;
const updateUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { params: { id: _id }, body, } = req;
        const updateUser = yield user_1.User.findByIdAndUpdate({ _id: _id }, { new: true });
        //const updateUser: IUser | null = await User.findByIdAndUpdate({ _id: _id }, body)
        const allUsers = yield user_1.User.find();
        res.status(200).json({
            success: true,
            message: 'User updated',
            user: updateUser,
        });
    }
    catch (error) {
        console.error('Error:', error);
        res
            .status(500)
            .json({ success: false, message: EError[req.body.language || 'en'] });
    }
});
exports.updateUser = updateUser;
// const updateUserJokes = async (req: Request, res: Response) => {
//   try {
//     const { id: _id } = req.params
//     const { jokeId }: { jokeId: number | undefined } = req.body
//     // Find the user by ID
//     const user = await User.findById(_id)
//     if (!user) {
//       res.status(404).json({ message: 'User not found' })
//       return
//     }
//     // Check if the 'jokeId' already exists in the 'jokes' array
//     if (!user.jokes.includes(jokeId! as never)) {
//       user.jokes.push(jokeId! as never)
//       await user.save()
//     }
//     res.status(200).json({ message: 'User jokes updated successfully', user })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
//   }
// }
const deleteUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const deletedUser = yield user_1.User.findByIdAndRemove(req.params.id);
        const allUsers = yield user_1.User.find();
        res.status(200).json({
            message: 'User deleted',
            user: deletedUser,
            users: allUsers,
        });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.deleteUser = deleteUser;
const loginUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const comparePassword = function (candidatePassword) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const isMatch = yield bcrypt_1.default.compare(candidatePassword, this.password);
                return isMatch;
            }
            catch (error) {
                console.error('Error:', error);
                return false;
            }
        });
    };
    let EInvalidLoginCredentials;
    (function (EInvalidLoginCredentials) {
        EInvalidLoginCredentials["en"] = "Invalid login credentials";
        EInvalidLoginCredentials["es"] = "Credenciales de inicio de sesi\u00F3n no v\u00E1lidas";
        EInvalidLoginCredentials["fr"] = "Informations de connexion invalides";
        EInvalidLoginCredentials["de"] = "Ung\u00FCltige Anmeldeinformationen";
        EInvalidLoginCredentials["pt"] = "Credenciais de login inv\u00E1lidas";
        EInvalidLoginCredentials["cs"] = "Neplatn\u00E9 p\u0159ihla\u0161ovac\u00ED \u00FAdaje";
    })(EInvalidLoginCredentials || (EInvalidLoginCredentials = {}));
    const { username, password, language } = req.body;
    const user = yield user_1.User.findOne({ username });
    if (!user) {
        res.status(401).json({
            message: `${EInvalidLoginCredentials[language]}` ||
                'Invalid login credentials - ',
        });
    }
    else if (user === null || user === void 0 ? void 0 : user.verified) {
        const passwordMatch = yield comparePassword.call(user, password);
        console.log('passwordMatch', passwordMatch);
        if (passwordMatch) {
            const token = generateToken(user._id);
            console.log('token, SUCCESS ', token);
            res
                .status(200)
                .json({ success: true, message: 'Successfully logged in', user, token });
        }
        else {
            res.status(401).json({ success: false, message: 'Invalid login credentials' });
        }
    }
    else if (!(user === null || user === void 0 ? void 0 : user.verified) && !(user === null || user === void 0 ? void 0 : user.token)) {
        try {
            const refresh = yield refreshExpiredToken(req, user._id);
            console.log('refresh 0', refresh);
            if (refresh === null || refresh === void 0 ? void 0 : refresh.success) {
                console.log(refresh === null || refresh === void 0 ? void 0 : refresh.message);
                res.status(401).json({ success: false, message: refresh.message, user });
                // res
                //   .status(401)
                //   .json({ success: false, message: 'User not verified. Please check your email ¤' })
            }
            else {
                console.log(refresh === null || refresh === void 0 ? void 0 : refresh.message);
                res.status(401).json({ success: false, message: refresh === null || refresh === void 0 ? void 0 : refresh.message });
            }
        }
        catch (error) {
            console.error(error);
            res.status(500).json({ message: EError[req.body.language || 'en'] });
        }
    }
    else if ((user === null || user === void 0 ? void 0 : user.token) && !(user === null || user === void 0 ? void 0 : user.verified)) {
        const decoded = verifyToken(user.token);
        if ((decoded === null || decoded === void 0 ? void 0 : decoded.exp) && (decoded === null || decoded === void 0 ? void 0 : decoded.exp) < Date.now() / 1000) {
            try {
                //generate new token
                const refresh = yield refreshExpiredToken(req, user._id);
                console.log('refresh 1', refresh);
                if (refresh === null || refresh === void 0 ? void 0 : refresh.success) {
                    console.log(refresh === null || refresh === void 0 ? void 0 : refresh.message);
                    res
                        .status(401)
                        .json({ success: false, message: refresh.message, user, token: user.token });
                }
                else {
                    console.log(refresh === null || refresh === void 0 ? void 0 : refresh.message);
                    res.status(401).json({ success: false, message: refresh === null || refresh === void 0 ? void 0 : refresh.message });
                }
            }
            catch (error) {
                console.error(error);
                res
                    .status(500)
                    .json({ message: EError[req.body.language || 'en'] });
            }
        }
        else if (!user.verified) {
            //generate new token
            const refresh = yield refreshExpiredToken(req, user._id);
            console.log('refresh 1', refresh);
            if (refresh === null || refresh === void 0 ? void 0 : refresh.success) {
                console.log(refresh === null || refresh === void 0 ? void 0 : refresh.message);
                res
                    .status(401)
                    .json({ success: false, message: refresh.message, user, token: user.token });
            }
            else {
                console.log(refresh === null || refresh === void 0 ? void 0 : refresh.message);
                res.status(401).json({ success: false, message: refresh === null || refresh === void 0 ? void 0 : refresh.message });
            }
            // res.status(401).json({ message: 'User not verified. Please check your email' })
        }
    }
});
exports.loginUser = loginUser;
// }
// const loginUser = async (req: Request, res: Response): Promise<void> => {
//   const comparePassword = async function (
//     this: IUser,
//     candidatePassword: string
//   ): Promise<boolean> {
//     try {
//       const isMatch: boolean = await bcrypt.compare(candidatePassword, this.password!)
//       return isMatch
//     } catch (error) {
//       console.error('Error:', error)
//       return false
//     }
//   }
//   try {
//     const { username, password } = req.body
//     const user: IUser | null = await User.findOne({ username })
//     if (!user) {
//       res.status(401).json({ message: 'User not found' })
//     } else if (!user.verified) {
//       res.status(401).json({ message: 'User not verified. Please check your email' })
//     } else {
//       const passwordMatch: boolean = await comparePassword.call(user, password)
//       if (passwordMatch) {
//         res.status(200).json({ message: 'User logged in' })
//       } else {
//         res.status(401).json({ message: 'Invalid login credentials' })
//       }
//     }
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
//   }
// }
const sendMail = (username, language, link) => {
    console.log(language);
    console.log(link);
    return new Promise((resolve, reject) => {
        transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: username,
            subject: EHelloWelcome[language] || 'Welcome',
            text: EEmailMessage[language] + ': ' + link ||
                'Please verify your email ' + ': ' + link,
        }, (error, info) => {
            if (error) {
                console.log(error);
                reject(error);
                return error;
            }
            else {
                console.log('Email sent: ' + info.response);
                resolve(info.response);
                return info.response;
            }
        });
    });
};
const registerUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    //User.collection.dropIndex('jokes_1')
    // try {
    let EMessage;
    (function (EMessage) {
        EMessage["en"] = "User registered. Please check your email for the verification link";
        EMessage["es"] = "Usuario registrado. Por favor, compruebe su correo electr\u00F3nico para el enlace de verificaci\u00F3n";
        EMessage["fr"] = "Utilisateur enregistr\u00E9. Veuillez v\u00E9rifier votre email pour le lien de v\u00E9rification";
        EMessage["de"] = "Benutzer registriert. Bitte \u00FCberpr\u00FCfen Sie Ihre E-Mail f\u00FCr den Best\u00E4tigungslink";
        EMessage["pt"] = "Usu\u00E1rio registrado. Por favor, verifique seu email para o link de verifica\u00E7\u00E3o";
        EMessage["cs"] = "U\u017Eivatel registrov\u00E1n. Pros\u00EDm, zkontrolujte sv\u016Fj email pro ov\u011B\u0159ovac\u00ED odkaz";
    })(EMessage || (EMessage = {}));
    const { username, password, jokes, language } = req.body;
    const saltRounds = 10;
    let ERegistrationFailed;
    (function (ERegistrationFailed) {
        ERegistrationFailed["en"] = "Registration failed";
        ERegistrationFailed["es"] = "Registro fallido";
        ERegistrationFailed["fr"] = "Inscription \u00E9chou\u00E9e";
        ERegistrationFailed["de"] = "Registrierung fehlgeschlagen";
        ERegistrationFailed["pt"] = "Registro falhou";
        ERegistrationFailed["cs"] = "Registrace se nezda\u0159ila";
    })(ERegistrationFailed || (ERegistrationFailed = {}));
    let EErrorCreatingToken;
    (function (EErrorCreatingToken) {
        EErrorCreatingToken["en"] = "Error creating token";
        EErrorCreatingToken["es"] = "Error al crear el token";
        EErrorCreatingToken["fr"] = "Erreur lors de la cr\u00E9ation du jeton";
        EErrorCreatingToken["de"] = "Fehler beim Erstellen des Tokens";
        EErrorCreatingToken["pt"] = "Erro ao criar token";
        EErrorCreatingToken["cs"] = "Chyba p\u0159i vytv\u00E1\u0159en\u00ED tokenu";
    })(EErrorCreatingToken || (EErrorCreatingToken = {}));
    let EPleaseCheckYourEmailIfYouHaveAlreadyRegistered;
    (function (EPleaseCheckYourEmailIfYouHaveAlreadyRegistered) {
        EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["en"] = "Please check your email if you have already registered";
        EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["es"] = "Por favor, compruebe su correo electr\u00F3nico si ya se ha registrado";
        EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["fr"] = "Veuillez v\u00E9rifier votre email si vous \u00EAtes d\u00E9j\u00E0 inscrit";
        EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["de"] = "Bitte \u00FCberpr\u00FCfen Sie Ihre E-Mail, wenn Sie sich bereits registriert haben";
        EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["pt"] = "Por favor, verifique seu email se voc\u00EA j\u00E1 se registrou";
        EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["cs"] = "Zkontrolujte sv\u016Fj email, pokud jste se ji\u017E zaregistrovali";
    })(EPleaseCheckYourEmailIfYouHaveAlreadyRegistered || (EPleaseCheckYourEmailIfYouHaveAlreadyRegistered = {}));
    try {
        bcrypt_1.default
            .hash(password, saltRounds)
            .then((hashedPassword) => {
            return user_1.User.findOne({ username }).then((user) => {
                if (user) {
                    res.status(401).json({
                        message: `${ERegistrationFailed[user.language]}. ${EPleaseCheckYourEmailIfYouHaveAlreadyRegistered[user.language]}` ||
                            'Registration failed, Please check your email if you have already registered',
                    });
                }
                else {
                    const newUser = new user_1.User({
                        username,
                        password: hashedPassword,
                        jokes,
                        language,
                        verified: false,
                    });
                    const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf';
                    jsonwebtoken_1.default.sign({ userId: newUser._id }, secret, { expiresIn: '1d' }, (err, token) => {
                        if (err) {
                            console.error(err);
                            res.status(500).json({
                                message: EErrorCreatingToken[newUser === null || newUser === void 0 ? void 0 : newUser.language] || 'Error creating token',
                            });
                        }
                        else {
                            const link = `${process.env.BASE_URI}/api/users/verify/${token}?lang=${language}`;
                            console.log('link 2', link);
                            newUser.token = token;
                            sendMail(username, language, link)
                                .then((result) => {
                                newUser.save().then((user) => {
                                    console.log('resulT', result);
                                    console.log('user', user);
                                    res.status(201).json({
                                        user,
                                        message: EMessage[language] || 'User registered',
                                    });
                                });
                            })
                                .catch((error) => {
                                console.log(error);
                                res.status(500).json({
                                    message: EErrorSendingMail[language] ||
                                        'Error sending mail',
                                });
                            });
                        }
                    });
                }
            });
        })
            .catch((error) => __awaiter(void 0, void 0, void 0, function* () {
            console.error(error);
            if (error.message === 'Token expired') {
                const user = yield user_1.User.findOne({ username });
                const refresh = yield refreshExpiredToken(req, user === null || user === void 0 ? void 0 : user._id);
                res.status(401).json({ success: false, message: refresh === null || refresh === void 0 ? void 0 : refresh.message });
            }
            else {
                const language = req.body.language || 'en';
                res
                    .status(500)
                    .json({ message: EError[language] || 'An error occurred *' });
            }
        }));
    }
    catch (error) {
        console.error('Error:', error);
        console.error('Error:', error);
        if (error.message === 'Token expired') {
            const user = yield user_1.User.findOne({ username });
            const refresh = yield refreshExpiredToken(req, user === null || user === void 0 ? void 0 : user._id);
            if (refresh === null || refresh === void 0 ? void 0 : refresh.success) {
                res.status(401).json({ success: true, message: refresh.message });
            }
            else {
                res.status(401).json({ success: false, message: refresh === null || refresh === void 0 ? void 0 : refresh.message });
            }
        }
        else {
            const language = req.body.language || 'en';
            res
                .status(500)
                .json({ message: EError[language] || 'An error occurred ¤' });
        }
    }
});
exports.registerUser = registerUser;
const refreshExpiredToken = (req, _id) => __awaiter(void 0, void 0, void 0, function* () {
    const body = req.body;
    const getUserById_ = (userId) => __awaiter(void 0, void 0, void 0, function* () {
        const user = yield user_1.User.findById(userId);
        if (user)
            return user;
        else
            return undefined;
    });
    let ENewTokenSentToEmail;
    (function (ENewTokenSentToEmail) {
        ENewTokenSentToEmail["en"] = "New token sent to email";
        ENewTokenSentToEmail["es"] = "Nuevo token enviado al correo electr\u00F3nico";
        ENewTokenSentToEmail["fr"] = "Nouveau jeton envoy\u00E9 par email";
        ENewTokenSentToEmail["de"] = "Neuer Token an E-Mail gesendet";
        ENewTokenSentToEmail["pt"] = "Novo token enviado para o email";
        ENewTokenSentToEmail["cs"] = "Nov\u00FD token odesl\u00E1n na email";
    })(ENewTokenSentToEmail || (ENewTokenSentToEmail = {}));
    let EUserNotVerified;
    (function (EUserNotVerified) {
        EUserNotVerified["en"] = "User not verified. Please check your email";
        EUserNotVerified["es"] = "Usuario no verificado. Por favor, compruebe su correo electr\u00F3nico";
        EUserNotVerified["fr"] = "Utilisateur non v\u00E9rifi\u00E9. Veuillez v\u00E9rifier votre email";
        EUserNotVerified["de"] = "Benutzer nicht verifiziert. Bitte \u00FCberpr\u00FCfen Sie Ihre E-Mail";
        EUserNotVerified["pt"] = "Usu\u00E1rio n\u00E3o verificado. Por favor, verifique seu email";
        EUserNotVerified["cs"] = "U\u017Eivatel nen\u00ED ov\u011B\u0159en. Zkontrolujte sv\u016Fj email";
    })(EUserNotVerified || (EUserNotVerified = {}));
    return new Promise((resolve, reject) => {
        var _a;
        try {
            let token = (_a = req.headers.authorization) === null || _a === void 0 ? void 0 : _a.split(' ')[1];
            if (!token) {
                getUserById_(_id)
                    .then((user) => {
                    if (user === null || user === void 0 ? void 0 : user.token) {
                        token = user.token;
                    }
                    else {
                        token = generateToken(_id);
                        if (!(user === null || user === void 0 ? void 0 : user.verified)) {
                            const link = `${process.env.BASE_URI}/api/users/verify/${token}?lang=${body.language}`;
                            console.log('link 3', link);
                            sendMail(body.username, body.language, link)
                                .then((r) => {
                                reject({
                                    success: false,
                                    message: `${EEmailMessage[body.language]} *,
                        ${ENewTokenSentToEmail[body.language]}` || 'Token sent',
                                    user,
                                });
                            })
                                .catch((error) => {
                                console.error(error);
                                reject({
                                    success: false,
                                    message: EErrorSendingMail[req.body.language] ||
                                        'Error sending mail ¤',
                                });
                            });
                        }
                        // reject(new Error('No token provided'))
                        // return
                    }
                })
                    .catch((error) => {
                    console.error(error);
                    reject({
                        success: false,
                        message: EError[req.body.language || 'en'] || '¤ Error',
                    });
                });
            }
            else {
                // Verify the expired token and get the user ID
                const decoded = verifyToken(token);
                // Create a new token for the user
                const newToken = generateToken(decoded === null || decoded === void 0 ? void 0 : decoded.userId);
                // Send the new token back to the client
                //resolve({ success: true, message: 'Token refreshed successfully', newToken })
                // Save the new token to the user
                getUserById_(decoded === null || decoded === void 0 ? void 0 : decoded.userId)
                    .then((user) => {
                    if (!user) {
                        reject(new Error(`${EErrorCreatingToken[body.language]} *`));
                        return;
                    }
                    const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf';
                    jsonwebtoken_1.default.sign({ userId: user._id }, secret, { expiresIn: '1d' }, (err, token) => {
                        if (err) {
                            console.error(err);
                            reject({
                                success: false,
                                message: EErrorCreatingToken[req.body.language] ||
                                    'Error creating token',
                            });
                        }
                        else {
                            user.token = token;
                            const link = `${process.env.BASE_URI}/api/users/verify/${token}?lang=${req.body.language}`;
                            console.log('link 1', link);
                            user
                                .save()
                                .then(() => {
                                sendMail(user.username, body.language, link);
                            })
                                .then((r) => {
                                resolve({
                                    success: true,
                                    message: ` ${EUserNotVerified[req.body.language]}. ${ENewTokenSentToEmail[body.language]}` || 'New link sent to email',
                                    user,
                                });
                            })
                                .catch((error) => {
                                console.error(error);
                                reject({
                                    success: false,
                                    message: EErrorSendingMail[req.body.language] ||
                                        'Error sending mail ¤',
                                });
                            });
                        }
                    });
                })
                    .catch((error) => {
                    console.error(error);
                    reject({
                        success: false,
                        message: EError[req.body.language || 'en'] || '¤ Error',
                    });
                });
            }
        }
        catch (error) {
            console.error('Error:', error);
            reject({
                success: false,
                message: EError[req.body.language || 'en'],
            });
        }
    });
});
exports.refreshExpiredToken = refreshExpiredToken;
// const refreshExpiredTokenOriginal = async (req: Request) => {
//   try {
//     const token = req.headers.authorization?.split(' ')[1] as IToken['token']
//     if (!token) throw new Error('No token provided')
//     // Verify the expired token and get the user ID
//     const decoded = verifyToken(token)
//     // Create a new token for the user
//     const newToken = generateToken(decoded?.userId)
//     // // Send the new token back to the client
//     //return { success: true, message: 'Token refreshed successfully', newToken }
//     const body = req.body as Pick<IUser, 'username' | 'language'>
//     const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
//     const user = await User.findOne({ username: body.username })
//     if (!user) {
//       return { success: false, message: `${EErrorCreatingToken[body.language]} *` }
//     } else {
//       // try {
//       jwt.sign({ userId: user?._id }, secret, { expiresIn: '1d' }, (err, token) => {
//         if (err) {
//           console.error(err)
//           return {
//             success: false,
//             message: EErrorCreatingToken[body.language] || 'Error creating token',
//           }
//         } else {
//           user.token = token
//           const link = `${process.env.BASE_URI}/api/users/verify/${token}?lang=${body.language}`
//           user
//             .save()
//             .then(() =>
//               sendMail(body.username, body.language as unknown as ELanguage, link)
//             )
//             .then((r) => {
//               console.log('Ärrä', r)
//               return {
//                 success: true,
//                 message: ETokenSent[body.language] || 'Token sent',
//                 user,
//               }
//             })
//             .catch((error) => {
//               console.log(error)
//               return {
//                 success: false,
//                 message: EErrorSendingMail[body.language] || 'Error sending mail ¤',
//               }
//             })
//         }
//       })
//       // } catch (error) {
//       //   console.error('Error:', error)
//       //   return {
//       //     success: false,
//       //     message: EError[(req.body.language as ELanguage) || 'en'] || '¤ Error',
//       //   }
//       // }
//     }
//   } catch (error) {
//     console.error('Error:', error)
//     return {
//       success: false,
//       message:
//         EError[(req.body.language as ELanguage) || 'en'] || 'Error refreshing token',
//     }
//   }
// }
const requestNewToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    if (!req.body.username) {
        res.status(400).json({ message: 'Username required' });
        return;
    }
    const username = req.body.username;
    const user = yield user_1.User.findOne({ username });
    if (!user) {
        res.status(404).json({ message: 'User not found' });
        return;
    }
    const token = generateToken(user._id);
    res.json({ token });
});
exports.requestNewToken = requestNewToken;
// const hashedPassword = await bcrypt.hash(password, saltRounds)
//     const user: IUser | null = await User.findOne({ username })
//     if (user) {
//       res.status(401).json({ message: 'Cannot register' })
//     } else {
//       const newUser: IUser = new User({
//         username,
//         password: hashedPassword,
//         jokes,
//         language,
//         verified: false,
//       })
//       enum EHelloWelcome {
//         en = "Hello, welcome to the Comedian's Companion",
//         es = 'Hola, bienvenido al Compañero del Comediante',
//         fr = 'Bonjour, bienvenue au Compagnon du Comédien',
//         de = 'Hallo, willkommen beim Begleiter des Komikers',
//         pt = 'Olá, bem-vindo ao Companheiro do Comediante',
//         cs = 'Ahoj, vítejte u Společníka komika',
//       }
//       enum EEmailMessage {
//         en = 'Please verify your email',
//         es = 'Por favor verifica tu correo electrónico',
//         fr = 'Veuillez vérifier votre email',
//         de = 'Bitte überprüfen Sie Ihre E-Mail',
//         pt = 'Por favor, verifique seu email',
//         cs = 'Prosím, ověřte svůj email',
//       }
//       enum EMessage {
//         en = 'User registered. Please check your email for the verification link',
//         es = 'Usuario registrado. Por favor, compruebe su correo electrónico para el enlace de verificación',
//         fr = 'Utilisateur enregistré. Veuillez vérifier votre email pour le lien de vérification',
//         de = 'Benutzer registriert. Bitte überprüfen Sie Ihre E-Mail für den Bestätigungslink',
//         pt = 'Usuário registrado. Por favor, verifique seu email para o link de verificação',
//         cs = 'Uživatel registrován. Prosím, zkontrolujte svůj email pro ověřovací odkaz',
//       }
//       const secret: Secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
//       const token = jwt.sign({ userId: newUser._id }, secret, { expiresIn: '1d' })
//       const link = `${process.env.BASE_URI}/api/users/verify/${token}?lang=${language}`
//       newUser.token = token
//       const sendMail = (): Promise<any> => {
//         return new Promise((resolve, reject) => {
//           transporter.sendMail(
//             {
//               from: `${process.env.EMAIL_USER}`,
//               to: username,
//               subject: EHelloWelcome[language as ELanguage],
//               text: `${EEmailMessage[language as ELanguage]}: ${link}`,
//             },
//             (error: Error | null, info: any) => {
//               if (error) {
//                 console.log(error)
//                 reject(error)
//                 res
//                   .status(500)
//                   .json({ message: EError[(req.body.language as ELanguage) || 'en'] })
//               } else {
//                 console.log('Email sent: ' + info.response)
//                 resolve(info.response)
//                 res.status(201).json({
//                   message: EMessage[language as ELanguage],
//                 })
//               }
//             }
//           )
//         })
//       }
//       enum EErrorSendingMail {
//         en = 'Error sending mail',
//         es = 'Error al enviar el correo',
//         fr = 'Erreur lors de l envoi du mail',
//         de = 'Fehler beim Senden der E-Mail',
//         pt = 'Erro ao enviar email',
//         cs = 'Chyba při odesílání emailu',
//       }
//       sendMail()
//         .then((result) => {
//           newUser.save()
//           console.log(result)
//         })
//         .catch((error) => {
//           console.log(error)
//           res.status(500).json({
//             message: EErrorSendingMail[(req.body.language as ELanguage) || 'en'],
//           })
//         })
//       // await transporter.sendMail({
//       //   from: `${process.env.EMAIL_USER}`,
//       //   to: username,
//       //   subject: EHelloWelcome[language as ELanguage],
//       //   text: `${EEmailMessage[language as ELanguage]}: ${link}`,
//       // })
//       // res.status(201).json({
//       //   message: EMessage[language as ELanguage],
//       // })
//     }
//   } catch (error) {
//     console.error('Error:', error)
//     const language = req.body.language || 'en'
//     res.status(500).json({ error, message: EError[language as ELanguage] })
//   }
// }
const verifyEmailToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _c, _d, _e, _f, _g;
    try {
        const token = req.params.token;
        const user = yield user_1.User.findOne({ token: token });
        if (user) {
            // Mark the user as verified and remove the verification token
            user.verified = true;
            user.token = undefined;
            yield user.save();
            //res.redirect('/api/users/verification-success')
            let EVerificationSuccessful;
            (function (EVerificationSuccessful) {
                EVerificationSuccessful["en"] = "Verification Successful";
                EVerificationSuccessful["es"] = "Verificaci\u00F3n exitosa";
                EVerificationSuccessful["fr"] = "V\u00E9rification r\u00E9ussie";
                EVerificationSuccessful["de"] = "Verifizierung erfolgreich";
                EVerificationSuccessful["pt"] = "Verifica\u00E7\u00E3o bem-sucedida";
                EVerificationSuccessful["cs"] = "\u00DAsp\u011B\u0161n\u00E1 verifikace";
            })(EVerificationSuccessful || (EVerificationSuccessful = {}));
            let EAccountSuccessfullyVerified;
            (function (EAccountSuccessfullyVerified) {
                EAccountSuccessfullyVerified["en"] = "Your account has been successfully verified";
                EAccountSuccessfullyVerified["es"] = "Su cuenta ha sido verificada con \u00E9xito";
                EAccountSuccessfullyVerified["fr"] = "Votre compte a \u00E9t\u00E9 v\u00E9rifi\u00E9 avec succ\u00E8s";
                EAccountSuccessfullyVerified["de"] = "Ihr Konto wurde erfolgreich verifiziert";
                EAccountSuccessfullyVerified["pt"] = "Sua conta foi verificada com sucesso";
                EAccountSuccessfullyVerified["cs"] = "V\u00E1\u0161 \u00FA\u010Det byl \u00FAsp\u011B\u0161n\u011B ov\u011B\u0159en";
            })(EAccountSuccessfullyVerified || (EAccountSuccessfullyVerified = {}));
            // let urlParams =
            //   typeof window !== 'undefined'
            //     ? new URLSearchParams(window.location.search)
            //     : undefined
            // let language = urlParams?.get('lang')
            const language = req.query.lang || 'en';
            const htmlResponse = `
    <html lang=${language !== null && language !== void 0 ? language : 'en'}>
      <head>
      
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style> 
        @import url('https://fonts.googleapis.com/css2?family=Caveat&family=Oswald:wght@500;600&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Lato:wght@100;300;400;700;900&display=swap');
          body {
            font-family: Lato, Helvetica, Arial, sans-serif;
            background-color: hsl(219, 100%, 10%);
            color: white;
            letter-spacing: -0.03em;
            display:flex;
            justify-content:center;
            align-items:center;
            min-height: 100vh;
          }
          body > div {
            margin: 0 auto;
            max-width: 800px;  
          }
          h1 {
            font-family: Oswald, Lato, Helvetica, Arial, sans-serif;
            text-align: center;
          }
          p {
            font-size: 18px;
            text-align: center;
          }
          a {
            color: white;
          }
        </style>
        <title>
        ${(_c = ETheComediansCompanion[language]) !== null && _c !== void 0 ? _c : "The Comedian' Companion"}</title>
      </head>
      <body>
      <div>
        <h1>${(_d = EVerificationSuccessful[language]) !== null && _d !== void 0 ? _d : 'Verification successful'}</h1>
        <p>${(_e = EAccountSuccessfullyVerified[language]) !== null && _e !== void 0 ? _e : 'Account successfully verified'}.</p>
        <p>
        <a href="https://react-az.jenniina.fi">${(_f = EBackToTheApp[language]) !== null && _f !== void 0 ? _f : 'Back to the app'}</a>
        </p>
      </div>
      </body>
    </html>
  `;
            res.send(htmlResponse);
        }
        else {
            const language = req.query.lang || 'en';
            let EVerificationFailed;
            (function (EVerificationFailed) {
                EVerificationFailed["en"] = "Already verified or verification token expired";
                EVerificationFailed["es"] = "Ya verificado o token de verificaci\u00F3n caducado";
                EVerificationFailed["fr"] = "D\u00E9j\u00E0 v\u00E9rifi\u00E9 ou jeton de v\u00E9rification expir\u00E9";
                EVerificationFailed["de"] = "Bereits verifiziert oder Verifizierungstoken abgelaufen";
                EVerificationFailed["pt"] = "J\u00E1 verificado ou token de verifica\u00E7\u00E3o expirado";
                EVerificationFailed["cs"] = "Ji\u017E ov\u011B\u0159eno nebo vypr\u0161el ov\u011B\u0159ovac\u00ED token";
            })(EVerificationFailed || (EVerificationFailed = {}));
            // const urlParams =
            //   typeof window !== 'undefined'
            //     ? new URLSearchParams(window.location.search)
            //     : undefined
            // const language = urlParams?.get('lang')
            const htmlResponse = `
    <html lang=${language !== null && language !== void 0 ? language : 'en'}>
      <head>
        <style> 
        @import url('https://fonts.googleapis.com/css2?family=Caveat&family=Oswald:wght@500;600&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Lato:wght@100;300;400;700;900&display=swap');
          body {
            font-family: Lato, Helvetica, Arial, sans-serif;
            background-color: hsl(219, 100%, 10%);
            color: white;
            letter-spacing: -0.03em;
            display:flex;
            justify-content:center;
            align-items:center;
            min-height: 100vh;
          }
          body > div {
            margin: 0 auto;
            max-width: 800px; 
          }
          h1 {
            font-family: Oswald, Lato, Helvetica, Arial, sans-serif;
            text-align: center;
          }
          p {
            font-size: 18px;
            text-align: center;
          }
          a {
            color: white;
          }
        </style> 
      </head>
      <body>
      <div>
        <h1>${EVerificationFailed[language]}</p>
        <p>
        <a href="https://react-az.jenniina.fi">${(_g = EBackToTheApp[language]) !== null && _g !== void 0 ? _g : 'Back to the app'}</a>
        </p>
      </div>
      </body>
    </html>
  `;
            res.send(htmlResponse);
            //res.status(400).json({ message: 'Invalid verification token' })
        }
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.verifyEmailToken = verifyEmailToken;
// const verificationSuccess = async (req: Request, res: Response): Promise<void> => {
//   const urlParams = new URLSearchParams(window.location.search)
//   const language = urlParams.get('lang')
//   enum EVerificationSuccessful {
//     en = 'Verification Successful',
//     es = 'Verificación exitosa',
//     fr = 'Vérification réussie',
//     de = 'Verifizierung erfolgreich',
//     pt = 'Verificação bem-sucedida',
//     cs = 'Úspěšná verifikace',
//   }
//   enum EAccountSuccessfullyVerified {
//     en = 'Your account has been successfully verified',
//     es = 'Su cuenta ha sido verificada con éxito',
//     fr = 'Votre compte a été vérifié avec succès',
//     de = 'Ihr Konto wurde erfolgreich verifiziert',
//     pt = 'Sua conta foi verificada com sucesso',
//     cs = 'Váš účet byl úspěšně ověřen',
//   }
//   enum EBackToTheApp {
//     en = 'Back to the App',
//     es = 'Volver a la aplicación',
//     fr = 'Retour à l application',
//     de = 'Zurück zur App',
//     pt = 'Voltar para o aplicativo',
//     cs = 'Zpět do aplikace',
//   }
//   const htmlResponse = `
//     <html lang=${language ?? 'en'}>
//       <head>
//         <meta charset="UTF-8">
//         <meta name="viewport" content="width=device-width, initial-scale=1.0">
//         <style>
//         @import url('https://fonts.googleapis.com/css2?family=Caveat&family=Oswald:wght@500;600&display=swap');
//         @import url('https://fonts.googleapis.com/css2?family=Lato:wght@100;300;400;700;900&display=swap');
//           body {
//             font-family: Lato, Helvetica, Arial, sans-serif;
//             background-color: hsl(219, 100%, 10%);
//             color: white;
//             letter-spacing: -0.03em;
//             display:flex;
//             justify-content:center;
//             align-items:center;
//             min-height: 100vh;
//           }
//           body > div {
//             margin: 0 auto;
//             max-width: 800px;
//           }
//           h1 {
//             font-family: Oswald, Lato, Helvetica, Arial, sans-serif;
//           }
//           p {
//             font-size: 18px;
//           }
//         </style>
//         <title>${ETheComediansCompanion[language as ELanguage]}</title>
//       </head>
//       <body>
//       <div>
//         <h1>${EVerificationSuccessful[language as ELanguage]}</h1>
//         <p>${EAccountSuccessfullyVerified}.</p>
//         <p>
//         <a href="https://react-az.jenniina.fi">${EBackToTheApp[language as ELanguage]}</a>
//         </p>
//       </div>
//       </body>
//     </html>
//   `
//   res.send(htmlResponse)
// }
const findUserByUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const userByUsername = yield user_1.User.findOne({
            username: req.params.username,
        });
        res.status(200).json({ user: userByUsername });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.findUserByUsername = findUserByUsername;
// const findUserByUsername = async (username: string): Promise<IUser | null> => {
//   try {
//     const userByUsername = await User.findOne({ username })
//     return userByUsername || null
//   } catch (error) {
//     console.error('Error:', error)
//     return null
//   }
// }
const logoutUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'User logged out' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.logoutUser = logoutUser;
const checkSession = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Session checked' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.checkSession = checkSession;
const forgotPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password forgot' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.forgotPassword = forgotPassword;
const resetPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password reset' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.resetPassword = resetPassword;
const resetPasswordToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password reset with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.resetPasswordToken = resetPasswordToken;
const changePassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password changed' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.changePassword = changePassword;
const changePasswordToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password changed with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.changePasswordToken = changePasswordToken;
const verifyEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email verified' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.verifyEmail = verifyEmail;
const changeEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email changed' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.changeEmail = changeEmail;
const changeEmailToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email changed with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.changeEmailToken = changeEmailToken;
const verifyUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username verified' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.verifyUsername = verifyUsername;
const verifyUsernameToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username verified with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.verifyUsernameToken = verifyUsernameToken;
const forgotUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username forgot' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.forgotUsername = forgotUsername;
const resetUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username reset' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.resetUsername = resetUsername;
const resetUsernameToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username reset with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.resetUsernameToken = resetUsernameToken;
const changeUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username changed' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.changeUsername = changeUsername;
const changeUsernameToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username changed with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.changeUsernameToken = changeUsernameToken;
