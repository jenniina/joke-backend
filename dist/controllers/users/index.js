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
exports.findUserByUsername = exports.verifyToken = exports.verifyTokenMiddleware = exports.generateToken = exports.changeUsernameToken = exports.changeUsername = exports.resetUsernameToken = exports.resetUsername = exports.forgotUsername = exports.verifyUsernameToken = exports.verifyUsername = exports.changeEmailToken = exports.changeEmail = exports.verifyEmailToken = exports.verifyEmail = exports.changePasswordToken = exports.changePassword = exports.resetPasswordToken = exports.resetPassword = exports.forgotPassword = exports.checkSession = exports.logoutUser = exports.registerUser = exports.loginUser = exports.deleteUser = exports.updateUser = exports.addUser = exports.getUser = exports.getUsers = exports.authenticateUser = exports.checkIfAdmin = exports.verificationSuccess = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const user_1 = require("../../models/user");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dotenv = require('dotenv');
dotenv.config();
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
    service: `${process.env.EMAIL_SERVICE}}`,
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
const generateToken = (userId) => {
    if (!userId)
        return undefined;
    const payload = { userId };
    const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf';
    const options = { expiresIn: '1d' };
    return jsonwebtoken_1.default.sign(payload, secret, options);
};
exports.generateToken = generateToken;
const verifyToken = (token) => {
    const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf';
    return jsonwebtoken_1.default.verify(token, secret);
};
exports.verifyToken = verifyToken;
const verifyTokenMiddleware = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const token = (_a = req.headers.authorization) === null || _a === void 0 ? void 0 : _a.split(' ')[1];
        if (!token)
            throw new Error('No token provided');
        const decoded = verifyToken(token);
        const user = yield user_1.User.findById(decoded.userId);
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
        const user = yield user_1.User.findById(decoded.userId);
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
        res.status(200).json({ user });
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
    }; //
    try {
        const { username, password } = req.body;
        const user = yield user_1.User.findOne({ username });
        if (!user) {
            res.status(401).json({ message: 'Invalid login credentials-' });
        }
        else if (!user.verified) {
            res.status(401).json({ message: 'User not verified. Please check your email' });
        }
        else {
            const passwordMatch = yield comparePassword.call(user, password);
            if (passwordMatch) {
                const token = generateToken(user._id);
                res.status(200).json({ message: 'Successfully logged in', user, token });
            }
            else {
                res.status(401).json({ message: 'Invalid login credentials' });
            }
        }
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.loginUser = loginUser;
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
const registerUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    //User.collection.dropIndex('jokes_1')
    try {
        const { username, password, jokes, language } = req.body;
        const saltRounds = 10;
        const hashedPassword = yield bcrypt_1.default.hash(password, saltRounds);
        const user = yield user_1.User.findOne({ username });
        if (user) {
            res.status(401).json({ message: 'Cannot register' });
        }
        else {
            const newUser = new user_1.User({
                username,
                password: hashedPassword,
                jokes,
                language,
                verified: false,
            });
            let EHelloWelcome;
            (function (EHelloWelcome) {
                EHelloWelcome["en"] = "Hello, welcome to the Comedian's Companion";
                EHelloWelcome["es"] = "Hola, bienvenido al Compa\u00F1ero del Comediante";
                EHelloWelcome["fr"] = "Bonjour, bienvenue au Compagnon du Com\u00E9dien";
                EHelloWelcome["de"] = "Hallo, willkommen beim Begleiter des Komikers";
                EHelloWelcome["pt"] = "Ol\u00E1, bem-vindo ao Companheiro do Comediante";
                EHelloWelcome["cs"] = "Ahoj, v\u00EDtejte u Spole\u010Dn\u00EDka komika";
            })(EHelloWelcome || (EHelloWelcome = {}));
            let EEmailMessage;
            (function (EEmailMessage) {
                EEmailMessage["en"] = "Please verify your email";
                EEmailMessage["es"] = "Por favor verifica tu correo electr\u00F3nico";
                EEmailMessage["fr"] = "Veuillez v\u00E9rifier votre email";
                EEmailMessage["de"] = "Bitte \u00FCberpr\u00FCfen Sie Ihre E-Mail";
                EEmailMessage["pt"] = "Por favor, verifique seu email";
                EEmailMessage["cs"] = "Pros\u00EDm, ov\u011B\u0159te sv\u016Fj email";
            })(EEmailMessage || (EEmailMessage = {}));
            let EMessage;
            (function (EMessage) {
                EMessage["en"] = "User registered. Please check your email for the verification link";
                EMessage["es"] = "Usuario registrado. Por favor, compruebe su correo electr\u00F3nico para el enlace de verificaci\u00F3n";
                EMessage["fr"] = "Utilisateur enregistr\u00E9. Veuillez v\u00E9rifier votre email pour le lien de v\u00E9rification";
                EMessage["de"] = "Benutzer registriert. Bitte \u00FCberpr\u00FCfen Sie Ihre E-Mail f\u00FCr den Best\u00E4tigungslink";
                EMessage["pt"] = "Usu\u00E1rio registrado. Por favor, verifique seu email para o link de verifica\u00E7\u00E3o";
                EMessage["cs"] = "U\u017Eivatel registrov\u00E1n. Pros\u00EDm, zkontrolujte sv\u016Fj email pro ov\u011B\u0159ovac\u00ED odkaz";
            })(EMessage || (EMessage = {}));
            const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf';
            const token = jsonwebtoken_1.default.sign({ userId: newUser._id }, secret, { expiresIn: '1d' });
            const link = `${process.env.BASE_URI}/verify/${token}?lang=${language}`;
            newUser.token = token;
            yield newUser.save();
            yield transporter.sendMail({
                from: `${process.env.EMAIL_USER}`,
                to: username,
                subject: EHelloWelcome[language],
                text: `${EEmailMessage[language]}: ${link}`,
            });
            res.status(201).json({
                message: EMessage[language],
            });
        }
    }
    catch (error) {
        console.error('Error:', error);
        const language = req.body.language || 'en';
        res.status(500).json({ message: EError[language] });
    }
});
exports.registerUser = registerUser;
const verificationSuccess = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const urlParams = new URLSearchParams(window.location.search);
    const language = urlParams.get('lang');
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
    let EBackToTheApp;
    (function (EBackToTheApp) {
        EBackToTheApp["en"] = "Back to the App";
        EBackToTheApp["es"] = "Volver a la aplicaci\u00F3n";
        EBackToTheApp["fr"] = "Retour \u00E0 l application";
        EBackToTheApp["de"] = "Zur\u00FCck zur App";
        EBackToTheApp["pt"] = "Voltar para o aplicativo";
        EBackToTheApp["cs"] = "Zp\u011Bt do aplikace";
    })(EBackToTheApp || (EBackToTheApp = {}));
    const htmlResponse = `
    <html>
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
          }
          p {
            font-size: 18px;
          }
        </style>
      </head>
      <body>
      <div>
        <h1 style="color: blue;">${EVerificationSuccessful[language]}</h1>
        <p>${EAccountSuccessfullyVerified}.</p>
        <p>
        <a href="https://react-az.jenniina.fi">${EBackToTheApp[language]}</a>
        </p>
      </div>
      </body>
    </html>
  `;
    res.send(htmlResponse);
});
exports.verificationSuccess = verificationSuccess;
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
const verifyEmailToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const token = req.params.token;
        const user = yield user_1.User.findOne({ verificationToken: token });
        if (user) {
            // Mark the user as verified and remove the verification token
            user.verified = true;
            user.token = undefined;
            yield user.save();
            res.redirect('/verification-success');
        }
        else {
            res.status(400).json({ message: 'Invalid verification token' });
        }
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: EError[req.body.language || 'en'] });
    }
});
exports.verifyEmailToken = verifyEmailToken;
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
