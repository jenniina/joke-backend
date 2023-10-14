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
exports.refreshExpiredToken = exports.requestNewToken = exports.findUserByUsername = exports.verifyToken = exports.verifyTokenMiddleware = exports.generateToken = exports.changeUsernameToken = exports.changeUsername = exports.resetUsernameToken = exports.resetUsername = exports.forgotUsername = exports.verifyUsernameToken = exports.verifyUsername = exports.changeEmailToken = exports.changeEmail = exports.verifyEmailToken = exports.verifyEmail = exports.changePasswordToken = exports.changePassword = exports.resetPasswordToken = exports.resetPassword = exports.forgotPassword = exports.logoutUser = exports.registerUser = exports.loginUser = exports.deleteUser = exports.updateUser = exports.addUser = exports.getUser = exports.getUsers = exports.authenticateUser = exports.checkIfAdmin = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const user_1 = require("../../models/user");
const flatted = require('flatted');
const crypto = require('crypto');
const key = crypto.randomBytes(32);
// const key = createHash('sha256')
//   .update(String(process.env.BRANCA_KEY))
//   .digest('base64')
//   .substr(0, 32)
const branca = require('branca')(key);
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
var ENoTokenProvided;
(function (ENoTokenProvided) {
    ENoTokenProvided["en"] = "No token provided";
    ENoTokenProvided["es"] = "No se proporcion\u00F3 ning\u00FAn token";
    ENoTokenProvided["fr"] = "Aucun jeton fourni";
    ENoTokenProvided["de"] = "Kein Token angegeben";
    ENoTokenProvided["pt"] = "Nenhum token fornecido";
    ENoTokenProvided["cs"] = "Nebyl poskytnut \u017E\u00E1dn\u00FD token";
})(ENoTokenProvided || (ENoTokenProvided = {}));
var ETokenVerified;
(function (ETokenVerified) {
    ETokenVerified["en"] = "Token verified";
    ETokenVerified["es"] = "Token verificado";
    ETokenVerified["fr"] = "Jeton v\u00E9rifi\u00E9";
    ETokenVerified["de"] = "Token verifiziert";
    ETokenVerified["pt"] = "Token verificado";
    ETokenVerified["cs"] = "Token ov\u011B\u0159en";
})(ETokenVerified || (ETokenVerified = {}));
var EPasswordReset;
(function (EPasswordReset) {
    EPasswordReset["en"] = "Password reset";
    EPasswordReset["es"] = "Restablecimiento de contrase\u00F1a";
    EPasswordReset["fr"] = "R\u00E9initialisation du mot de passe";
    EPasswordReset["de"] = "Passwort zur\u00FCcksetzen";
    EPasswordReset["pt"] = "Redefini\u00E7\u00E3o de senha";
    EPasswordReset["cs"] = "Obnoven\u00ED hesla";
})(EPasswordReset || (EPasswordReset = {}));
var EResetPassword;
(function (EResetPassword) {
    EResetPassword["en"] = "Reset password";
    EResetPassword["es"] = "Restablecer la contrase\u00F1a";
    EResetPassword["fr"] = "R\u00E9initialiser le mot de passe";
    EResetPassword["de"] = "Passwort zur\u00FCcksetzen";
    EResetPassword["pt"] = "Redefinir senha";
    EResetPassword["cs"] = "Obnovit heslo";
})(EResetPassword || (EResetPassword = {}));
var ENewPassword;
(function (ENewPassword) {
    ENewPassword["en"] = "New Password";
    ENewPassword["es"] = "Nueva contrase\u00F1a";
    ENewPassword["fr"] = "Nouveau mot de passe";
    ENewPassword["de"] = "Neues Kennwort";
    ENewPassword["pt"] = "Nova senha";
    ENewPassword["cs"] = "Nov\u00E9 heslo";
})(ENewPassword || (ENewPassword = {}));
var EConfirmPassword;
(function (EConfirmPassword) {
    EConfirmPassword["en"] = "Confirm Password";
    EConfirmPassword["es"] = "Confirmar contrase\u00F1a";
    EConfirmPassword["fr"] = "Confirmez le mot de passe";
    EConfirmPassword["de"] = "Kennwort best\u00E4tigen";
    EConfirmPassword["pt"] = "Confirme a Senha";
    EConfirmPassword["cs"] = "Potvr\u010Fte heslo";
})(EConfirmPassword || (EConfirmPassword = {}));
var EInvalidLoginCredentials;
(function (EInvalidLoginCredentials) {
    EInvalidLoginCredentials["en"] = "Invalid login credentials";
    EInvalidLoginCredentials["es"] = "Credenciales de inicio de sesi\u00F3n no v\u00E1lidas";
    EInvalidLoginCredentials["fr"] = "Informations de connexion invalides";
    EInvalidLoginCredentials["de"] = "Ung\u00FCltige Anmeldeinformationen";
    EInvalidLoginCredentials["pt"] = "Credenciais de login inv\u00E1lidas";
    EInvalidLoginCredentials["cs"] = "Neplatn\u00E9 p\u0159ihla\u0161ovac\u00ED \u00FAdaje";
})(EInvalidLoginCredentials || (EInvalidLoginCredentials = {}));
var EInvalidOrMissingToken;
(function (EInvalidOrMissingToken) {
    EInvalidOrMissingToken["en"] = "Invalid or missing request";
    EInvalidOrMissingToken["es"] = "Solicitud inv\u00E1lida o faltante";
    EInvalidOrMissingToken["fr"] = "Demande invalide ou manquante";
    EInvalidOrMissingToken["de"] = "Ung\u00FCltige oder fehlende Anfrage";
    EInvalidOrMissingToken["pt"] = "Solicita\u00E7\u00E3o inv\u00E1lida ou ausente";
    EInvalidOrMissingToken["cs"] = "Neplatn\u00FD nebo chyb\u011Bj\u00EDc\u00ED po\u017Eadavek";
})(EInvalidOrMissingToken || (EInvalidOrMissingToken = {}));
var EPleaseCheckYourEmailIfYouHaveAlreadyRegistered;
(function (EPleaseCheckYourEmailIfYouHaveAlreadyRegistered) {
    EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["en"] = "Please check your email if you have already registered";
    EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["es"] = "Por favor, compruebe su correo electr\u00F3nico si ya se ha registrado";
    EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["fr"] = "Veuillez v\u00E9rifier votre email si vous \u00EAtes d\u00E9j\u00E0 inscrit";
    EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["de"] = "Bitte \u00FCberpr\u00FCfen Sie Ihre E-Mail, wenn Sie sich bereits registriert haben";
    EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["pt"] = "Por favor, verifique seu email se voc\u00EA j\u00E1 se registrou";
    EPleaseCheckYourEmailIfYouHaveAlreadyRegistered["cs"] = "Zkontrolujte sv\u016Fj email, pokud jste se ji\u017E zaregistrovali";
})(EPleaseCheckYourEmailIfYouHaveAlreadyRegistered || (EPleaseCheckYourEmailIfYouHaveAlreadyRegistered = {}));
var ELogInAtTheAppOrRequestANewPasswordResetToken;
(function (ELogInAtTheAppOrRequestANewPasswordResetToken) {
    ELogInAtTheAppOrRequestANewPasswordResetToken["en"] = "Log in at the app or request a new password reset token";
    ELogInAtTheAppOrRequestANewPasswordResetToken["es"] = "Inicie sesi\u00F3n en la aplicaci\u00F3n o solicite un nuevo token de restablecimiento de contrase\u00F1a";
    ELogInAtTheAppOrRequestANewPasswordResetToken["fr"] = "Connectez-vous \u00E0 l application ou demandez un nouveau jeton de r\u00E9initialisation de mot de passe";
    ELogInAtTheAppOrRequestANewPasswordResetToken["de"] = "Melden Sie sich in der App an oder fordern Sie einen neuen Token zum Zur\u00FCcksetzen des Passworts an";
    ELogInAtTheAppOrRequestANewPasswordResetToken["pt"] = "Fa\u00E7a login no aplicativo ou solicite um novo token de redefini\u00E7\u00E3o de senha";
    ELogInAtTheAppOrRequestANewPasswordResetToken["cs"] = "P\u0159ihlaste se do aplikace nebo po\u017E\u00E1dejte o nov\u00FD token pro obnoven\u00ED hesla";
})(ELogInAtTheAppOrRequestANewPasswordResetToken || (ELogInAtTheAppOrRequestANewPasswordResetToken = {}));
var EAccessDeniedAdminPrivilegeRequired;
(function (EAccessDeniedAdminPrivilegeRequired) {
    EAccessDeniedAdminPrivilegeRequired["en"] = "Access denied. Admin privilege required.";
    EAccessDeniedAdminPrivilegeRequired["es"] = "Acceso denegado. Se requiere privilegio de administrador.";
    EAccessDeniedAdminPrivilegeRequired["fr"] = "Acc\u00E8s refus\u00E9. Privil\u00E8ge administrateur requis.";
    EAccessDeniedAdminPrivilegeRequired["de"] = "Zugriff verweigert. Admin-Berechtigung erforderlich.";
    EAccessDeniedAdminPrivilegeRequired["pt"] = "Acesso negado. Privil\u00E9gio de administrador necess\u00E1rio.";
    EAccessDeniedAdminPrivilegeRequired["cs"] = "P\u0159\u00EDstup odep\u0159en. Vy\u017Eaduje se opr\u00E1vn\u011Bn\u00ED spr\u00E1vce.";
})(EAccessDeniedAdminPrivilegeRequired || (EAccessDeniedAdminPrivilegeRequired = {}));
var EAuthenticationFailed;
(function (EAuthenticationFailed) {
    EAuthenticationFailed["en"] = "Authentication failed";
    EAuthenticationFailed["es"] = "Autenticaci\u00F3n fallida";
    EAuthenticationFailed["fr"] = "L authentification a \u00E9chou\u00E9";
    EAuthenticationFailed["de"] = "Authentifizierung fehlgeschlagen";
    EAuthenticationFailed["pt"] = "Autentica\u00E7\u00E3o falhou";
    EAuthenticationFailed["cs"] = "Autentizace selhala";
})(EAuthenticationFailed || (EAuthenticationFailed = {}));
var EUserAdded;
(function (EUserAdded) {
    EUserAdded["en"] = "User added";
    EUserAdded["es"] = "Usuario a\u00F1adido";
    EUserAdded["fr"] = "Utilisateur ajout\u00E9";
    EUserAdded["de"] = "Benutzer hinzugef\u00FCgt";
    EUserAdded["pt"] = "Usu\u00E1rio adicionado";
    EUserAdded["cs"] = "U\u017Eivatel p\u0159id\u00E1n";
})(EUserAdded || (EUserAdded = {}));
var EUserUpdated;
(function (EUserUpdated) {
    EUserUpdated["en"] = "User updated";
    EUserUpdated["es"] = "Usuario actualizado";
    EUserUpdated["fr"] = "Utilisateur mis \u00E0 jour";
    EUserUpdated["de"] = "Benutzer aktualisiert";
    EUserUpdated["pt"] = "Usu\u00E1rio atualizado";
    EUserUpdated["cs"] = "U\u017Eivatel aktualizov\u00E1n";
})(EUserUpdated || (EUserUpdated = {}));
var EUserDeleted;
(function (EUserDeleted) {
    EUserDeleted["en"] = "User deleted";
    EUserDeleted["es"] = "Usuario borrado";
    EUserDeleted["fr"] = "Utilisateur supprim\u00E9";
    EUserDeleted["de"] = "Benutzer gel\u00F6scht";
    EUserDeleted["pt"] = "Usu\u00E1rio exclu\u00EDdo";
    EUserDeleted["cs"] = "U\u017Eivatel smaz\u00E1n";
})(EUserDeleted || (EUserDeleted = {}));
var EYouHaveLoggedOut;
(function (EYouHaveLoggedOut) {
    EYouHaveLoggedOut["en"] = "You have logged out";
    EYouHaveLoggedOut["es"] = "Has cerrado la sesi\u00F3n";
    EYouHaveLoggedOut["fr"] = "Vous vous \u00EAtes d\u00E9connect\u00E9";
    EYouHaveLoggedOut["de"] = "Sie haben sich abgemeldet";
    EYouHaveLoggedOut["pt"] = "Voc\u00EA saiu";
    EYouHaveLoggedOut["cs"] = "Odhl\u00E1sili jste se";
})(EYouHaveLoggedOut || (EYouHaveLoggedOut = {}));
var EUsernameRequired;
(function (EUsernameRequired) {
    EUsernameRequired["en"] = "Username required";
    EUsernameRequired["es"] = "Nombre de usuario requerido";
    EUsernameRequired["fr"] = "Nom d utilisateur requis";
    EUsernameRequired["de"] = "Benutzername erforderlich";
    EUsernameRequired["pt"] = "Nome de usu\u00E1rio obrigat\u00F3rio";
    EUsernameRequired["cs"] = "Vy\u017Eadov\u00E1no u\u017Eivatelsk\u00E9 jm\u00E9no";
})(EUsernameRequired || (EUsernameRequired = {}));
var ESuccessfullyLoggedIn;
(function (ESuccessfullyLoggedIn) {
    ESuccessfullyLoggedIn["en"] = "Successfully logged in";
    ESuccessfullyLoggedIn["es"] = "Iniciado sesi\u00F3n con \u00E9xito";
    ESuccessfullyLoggedIn["fr"] = "Connect\u00E9 avec succ\u00E8s";
    ESuccessfullyLoggedIn["de"] = "Erfolgreich angemeldet";
    ESuccessfullyLoggedIn["pt"] = "Logado com sucesso";
    ESuccessfullyLoggedIn["cs"] = "\u00DAsp\u011B\u0161n\u011B p\u0159ihl\u00E1\u0161en";
})(ESuccessfullyLoggedIn || (ESuccessfullyLoggedIn = {}));
const generateToken = (id) => {
    if (!id)
        return undefined;
    // const id = JSON.stringify({
    //   userId: userId,
    // })
    const json = flatted.stringify({
        userId: id,
    });
    return branca.encode(json);
    // const payload: ITokenPayload = { userId: userId }
    // const secret: Secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
    // const options = { expiresIn: '1d' }
    // return jwt.sign(payload, secret, options, (err, token) => {
    //   if (err) {
    //     console.error(err)
    //     return undefined
    //   } else {
    //     return token
    //   }
    // }) as IToken['token']
};
exports.generateToken = generateToken;
// const verifyToken = (token: string): ITokenPayload => {
//   const secret: Secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
//   return jwt.verify(token, secret) as ITokenPayload
// }
const verifyToken = (token) => {
    const json = branca.decode(token);
    return JSON.parse(json);
    // const secret: Secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
    // try {
    //   if (token) return jwt.verify(token, secret) as JwtPayload
    //   else return undefined
    // } catch (error) {
    //   if ((error as Error).name === 'TokenExpiredError') {
    //     throw new Error('Token expired')
    //   } else {
    //     throw error // Re-throw other errors
    //   }
    // }
};
exports.verifyToken = verifyToken;
const verifyTokenMiddleware = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const token = (_a = req.headers.authorization) === null || _a === void 0 ? void 0 : _a.split(' ')[1];
        if (!token)
            throw new Error(ENoTokenProvided[req.body.language || 'en']);
        const decoded = verifyToken(token);
        const user = yield user_1.User.findById(decoded === null || decoded === void 0 ? void 0 : decoded.userId);
        if (!user)
            throw new Error('User not found');
        res.status(200).json({
            message: ETokenVerified[req.body.language || 'en'] || 'Token verified',
        });
    }
    catch (error) {
        console.error('Error:', error);
        res
            .status(500)
            .json({ success: false, message: EError[req.body.language || 'en'] });
    }
});
exports.verifyTokenMiddleware = verifyTokenMiddleware;
// Middleware to check if the user has admin role
const checkIfAdmin = (req, res, next) => {
    const user = req.body;
    const language = user.language;
    if (user && user.role > 2) {
        // User is an admin, allow access
        next();
    }
    else {
        // User is not an admin, deny access
        res.status(403).json({
            message: EAccessDeniedAdminPrivilegeRequired[language] ||
                'Access denied. Admin privilege required.',
        });
    }
};
exports.checkIfAdmin = checkIfAdmin;
const authenticateUser = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    try {
        const token = (_b = req.headers.authorization) === null || _b === void 0 ? void 0 : _b.split(' ')[1];
        if (!token)
            throw new Error(ENoTokenProvided[req.body.language || 'en']);
        const decoded = verifyToken(token);
        const user = yield user_1.User.findById(decoded === null || decoded === void 0 ? void 0 : decoded.userId);
        const language = (user === null || user === void 0 ? void 0 : user.language) || 'en';
        if (!user)
            throw new Error(EAuthenticationFailed[language]);
        // Attach user information to the request object
        req.body = user;
        next();
    }
    catch (error) {
        console.error('Error:', error);
        res.status(401).json({ success: false, message: 'Authentication failed' });
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
        res
            .status(500)
            .json({ success: false, message: EError[req.body.language || 'en'] });
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
        res
            .status(500)
            .json({ success: false, message: EError[req.body.language || 'en'] });
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
        res.status(201).json({
            success: true,
            message: EUserAdded[newUser.language || 'en'],
            user: newUser,
            users: allUsers,
        });
    }
    catch (error) {
        console.error('Error:', error);
        res
            .status(500)
            .json({ success: false, message: EError[req.body.language || 'en'] });
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
            message: EUserUpdated[(updateUser === null || updateUser === void 0 ? void 0 : updateUser.language) || 'en'],
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
            success: true,
            message: EUserDeleted[(deletedUser === null || deletedUser === void 0 ? void 0 : deletedUser.language) || 'en'],
            user: deletedUser,
            users: allUsers,
        });
    }
    catch (error) {
        console.error('Error:', error);
        res
            .status(500)
            .json({ success: false, message: EError[req.body.language || 'en'] });
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
        if (passwordMatch) {
            const token = generateToken(user._id);
            res.status(200).json({
                success: true,
                message: ESuccessfullyLoggedIn[user.language || 'en'],
                user,
                token,
            });
        }
        else {
            res.status(401).json({
                success: false,
                message: EInvalidLoginCredentials[user.language || 'en'],
            });
        }
    }
    else if (!(user === null || user === void 0 ? void 0 : user.verified) && !(user === null || user === void 0 ? void 0 : user.token)) {
        try {
            const refresh = yield refreshExpiredToken(req, user._id);
            if (refresh === null || refresh === void 0 ? void 0 : refresh.success) {
                res.status(401).json({ success: false, message: refresh.message, user });
                // res
                //   .status(401)
                //   .json({ success: false, message: 'User not verified. Please check your email ¤' })
            }
            else {
                res.status(401).json({ success: false, message: refresh === null || refresh === void 0 ? void 0 : refresh.message });
            }
        }
        catch (error) {
            console.error(error);
            res.status(500).json({
                success: false,
                message: EError[req.body.language || 'en'],
            });
        }
    }
    else if ((user === null || user === void 0 ? void 0 : user.token) && !(user === null || user === void 0 ? void 0 : user.verified)) {
        const decoded = verifyToken(user.token);
        if ((decoded === null || decoded === void 0 ? void 0 : decoded.exp) && (decoded === null || decoded === void 0 ? void 0 : decoded.exp) < Date.now() / 1000) {
            try {
                //generate new token
                const refresh = yield refreshExpiredToken(req, user._id);
                if (refresh === null || refresh === void 0 ? void 0 : refresh.success) {
                    res
                        .status(401)
                        .json({ success: false, message: refresh.message, user, token: user.token });
                }
                else {
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
            if (refresh === null || refresh === void 0 ? void 0 : refresh.success) {
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
const forgotPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username } = req.body;
    const language = req.body.language || 'en';
    const user = yield user_1.User.findOne({ username });
    if (!user) {
        res.status(401).json({ success: false, message: EError[language] });
    }
    else if (user) {
        try {
            // const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
            // const userId = { userId: user._id }
            //const token = jwt.sign(userId, secret, { expiresIn: '1d' })
            //const token = '1234567890'
            const token = generateToken(user._id);
            const link = `${process.env.BASE_URI}/api/users/reset/${token}?lang=${language}`;
            //User.findOneAndUpdate({ username }, { $set: { resetToken: token } })
            yield user_1.User.findOneAndUpdate({ username }, { resetToken: token });
            sendMail(EPasswordReset[language], EResetPassword[language], username, language, link)
                .then((result) => {
                res.status(200).json({
                    success: true,
                    message: ETokenSent[language] || 'Token sent',
                });
            })
                .catch((error) => {
                console.log(error);
                res.status(500).json({
                    success: false,
                    message: EErrorSendingMail[language] || 'Error sending mail',
                });
            });
        }
        catch (error) {
            console.error('Error:', error);
            res.status(500).json({
                success: false,
                message: EError[language || 'en'] || 'Error ¤',
            });
        }
    }
    else {
        res
            .status(401)
            .json({ success: false, message: `${EError[language]} *` });
    }
});
exports.forgotPassword = forgotPassword;
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
const sendMail = (subject, message, username, language, link) => {
    return new Promise((resolve, reject) => {
        transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: username,
            subject: subject || 'Welcome',
            text: message + ': ' + link || link,
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
            return user_1.User.findOne({ username })
                .then((user) => {
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
                    // const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
                    // jwt.sign(
                    //   { userId: newUser._id },
                    //   secret,
                    //   { expiresIn: '1d' },
                    //   (err, token) => {
                    //     if (err) {
                    //       console.error(err)
                    //       res.status(500).json({
                    //         message:
                    //           EErrorCreatingToken[newUser?.language] || 'Error creating token',
                    //       })
                    // } else {
                    const token = generateToken(newUser._id);
                    const link = `${process.env.BASE_URI}/api/users/verify/${token}?lang=${language}`;
                    newUser.token = token;
                    sendMail(EHelloWelcome[language], EEmailMessage[language], username, language, link)
                        .then((result) => {
                        newUser.save().then((user) => {
                            res.status(201).json({
                                success: true,
                                user,
                                message: EMessage[language] || 'User registered',
                            });
                        });
                    })
                        .catch((error) => {
                        console.log(error);
                        res.status(500).json({
                            message: EErrorSendingMail[language] || 'Error sending mail',
                        });
                    });
                    // }
                }
                // )
                // }
            })
                .catch((error) => {
                console.error(error);
                res.status(500).json({
                    success: false,
                    message: EError[language || 'en'] || 'An error occurred',
                });
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
                res.status(500).json({
                    success: false,
                    message: EError[language] || 'An error occurred *',
                });
            }
        }));
    }
    catch (error) {
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
            res.status(500).json({
                success: false,
                message: EError[language] || 'An error occurred ¤',
            });
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
                            sendMail(EHelloWelcome[body.language], EEmailMessage[body.language], body.username, body.language, link)
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
                //// Create a new token for the user
                //const newToken = generateToken(decoded?.userId)
                //// Send the new token back to the client
                //resolve({ success: true, message: 'Token refreshed successfully', newToken })
                // Save the new token to the user
                getUserById_(decoded === null || decoded === void 0 ? void 0 : decoded.userId)
                    .then((user) => {
                    if (!user) {
                        reject(new Error(`${EErrorCreatingToken[body.language]} *`));
                        return;
                    }
                    else {
                        // const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
                        // jwt.sign(
                        //   { userId: user._id },
                        //   secret,
                        //   { expiresIn: '1d' },
                        //   (err, token) => {
                        //     if (err) {
                        //       console.error(err)
                        //       reject({
                        //         success: false,
                        //         message:
                        //           EErrorCreatingToken[req.body.language as ELanguage] ||
                        //           'Error creating token',
                        //       })
                        //     } else {
                        user.token = token;
                        const link = `${process.env.BASE_URI}/api/users/verify/${token}?lang=${req.body.language}`;
                        user
                            .save()
                            .then(() => {
                            sendMail(EHelloWelcome[body.language], EEmailMessage[body.language], user.username, body.language, link);
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
                    // }
                    // )
                    // }
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
    const language = req.body.language || req.query.lang || 'en';
    if (!req.body.username) {
        res
            .status(400)
            .json({ success: false, message: EUsernameRequired[language] });
        return;
    }
    const username = req.body.username;
    try {
        const user = yield user_1.User.findOne({ username });
        if (!user) {
            res
                .status(404)
                .json({ success: false, message: `${EError[language]} -` });
            return;
        }
        const token = generateToken(user._id);
        if (token) {
            res.json({
                success: true,
                message: `${EError[language]}. ${EErrorCreatingToken} ~`,
                token,
            });
        }
        else {
            res.status(500).json({
                success: false,
                message: `${EError[language]}. ${EErrorCreatingToken} ¤`,
            });
        }
    }
    catch (_c) {
        res.status(500).json({
            success: false,
            message: `${EError[language]}. ${EErrorCreatingToken} *`,
        });
    }
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
    var _d, _e, _f, _g, _h;
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
        ${(_d = ETheComediansCompanion[language]) !== null && _d !== void 0 ? _d : "The Comedian' Companion"}</title>
      </head>
      <body>
      <div>
        <h1>${(_e = EVerificationSuccessful[language]) !== null && _e !== void 0 ? _e : 'Verification successful'}</h1>
        <p>${(_f = EAccountSuccessfullyVerified[language]) !== null && _f !== void 0 ? _f : 'Account successfully verified'}.</p>
        <p>
        <a href="https://react-az.jenniina.fi">${(_g = EBackToTheApp[language]) !== null && _g !== void 0 ? _g : 'Back to the app'}</a>
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
        <a href="https://react-az.jenniina.fi">${(_h = EBackToTheApp[language]) !== null && _h !== void 0 ? _h : 'Back to the app'}</a>
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
        res
            .status(500)
            .json({ success: false, message: EError[req.body.language || 'en'] });
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
        res
            .status(500)
            .json({ success: false, message: EError[req.body.language || 'en'] });
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
    const language = req.body.language || req.query.lang || 'en';
    try {
        res.status(200).json({
            success: true,
            message: EYouHaveLoggedOut[language],
        });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, message: EError[language] });
    }
});
exports.logoutUser = logoutUser;
const resetPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _j, _k, _l, _m, _o, _p, _q;
    const { token } = req.params;
    const language = req.query.lang || 'en';
    try {
        // Validate the token
        const user = yield user_1.User.findOne({ resetToken: token });
        if (!user) {
            res.send(`
      <!DOCTYPE html>
      <html lang=${language}>
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
        ${(_j = ETheComediansCompanion[language]) !== null && _j !== void 0 ? _j : "The Comedian' Companion"}</title>
      </head>
      <body>
      <div>
        <h1>
          ${EInvalidOrMissingToken[language] || 'Invalid or expired token'}
        </h1>
        <p>${ELogInAtTheAppOrRequestANewPasswordResetToken[language] ||
                'Check the app to request a new password reset token. '}</p> 
        <p>
        <a href="https://react-az.jenniina.fi">${(_k = EBackToTheApp[language]) !== null && _k !== void 0 ? _k : 'Back to the app'}</a>
        </p>
      </div>
      </body>
    </html>
    `);
            // res.status(400).json({
            //   success: false,
            //   message:
            //     `${EInvalidOrMissingToken[language as ELanguage]}. ${
            //       ELogInAtTheAppOrRequestANewPasswordResetToken[language as ELanguage]
            //     }` || 'Invalid or expired token',
            // })
        }
        else if (user) {
            const htmlResponse = `
    <html lang=${language}>
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
        ${(_l = ETheComediansCompanion[language]) !== null && _l !== void 0 ? _l : "The Comedian' Companion"}</title>
      </head>
      <body>
      <div>
        <h1>${(_m = EPasswordReset[language]) !== null && _m !== void 0 ? _m : 'Password Reset'}</h1>
        <form action="/api/users/reset/${token}?lang=${language}" method="post">
        <label for="newPassword">${(_o = ENewPassword[language]) !== null && _o !== void 0 ? _o : 'New password'}:</label>
        <input type="password" id="newPassword" name="newPassword" required>
        <label for="confirmPassword">${(_p = EConfirmPassword[language]) !== null && _p !== void 0 ? _p : 'Confirm Password'}:</label>
        <input type="password" id="confirmPassword" name="confirmPassword" required>
        <button type="submit">${(_q = EResetPassword[language]) !== null && _q !== void 0 ? _q : 'Reset password'}</button>
      </form> 
      </div>
      </body>
    </html>
  `;
            res.send(htmlResponse);
        }
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal Server Error *' });
    }
});
exports.resetPassword = resetPassword;
const resetPasswordToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _r, _s, _t, _u, _v, _w, _x, _y;
    const { token } = req.params;
    const { newPassword, confirmPassword } = req.body;
    const language = req.query.lang || 'en';
    let EPasswordResetSuccessfully;
    (function (EPasswordResetSuccessfully) {
        EPasswordResetSuccessfully["en"] = "Password reset successfully";
        EPasswordResetSuccessfully["es"] = "Restablecimiento de contrase\u00F1a exitoso";
        EPasswordResetSuccessfully["fr"] = "R\u00E9initialisation du mot de passe r\u00E9ussie";
        EPasswordResetSuccessfully["de"] = "Passwort erfolgreich zur\u00FCckgesetzt";
        EPasswordResetSuccessfully["pt"] = "Redefini\u00E7\u00E3o de senha bem-sucedida";
        EPasswordResetSuccessfully["cs"] = "Obnoven\u00ED hesla bylo \u00FAsp\u011B\u0161n\u00E9";
    })(EPasswordResetSuccessfully || (EPasswordResetSuccessfully = {}));
    let EPasswordsDoNotMatch;
    (function (EPasswordsDoNotMatch) {
        EPasswordsDoNotMatch["en"] = "Passwords do not match";
        EPasswordsDoNotMatch["es"] = "Las contrase\u00F1as no coinciden";
        EPasswordsDoNotMatch["fr"] = "Les mots de passe ne correspondent pas";
        EPasswordsDoNotMatch["de"] = "Passw\u00F6rter stimmen nicht \u00FCberein";
        EPasswordsDoNotMatch["pt"] = "As senhas n\u00E3o coincidem";
        EPasswordsDoNotMatch["cs"] = "Hesla se neshoduj\u00ED";
    })(EPasswordsDoNotMatch || (EPasswordsDoNotMatch = {}));
    try {
        // Validate the token
        const user = yield user_1.User.findOne({ resetToken: token });
        if (!user) {
            res.status(400).json({ message: 'Invalid or expired token' });
        }
        else if (user) {
            // Check if newPassword and confirmPassword match
            if (newPassword !== confirmPassword) {
                // res.status(400).json({
                //   success: false,
                //   message:
                //     EPasswordsDoNotMatch[language as keyof typeof EPasswordsDoNotMatch] ||
                //     'Passwords do not match',
                // })
                const htmlResponse = `
    <html lang=${language}>
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
        ${(_r = ETheComediansCompanion[language]) !== null && _r !== void 0 ? _r : "The Comedian' Companion"}</title>
      </head>
      <body>
      <div>
        <h1>${(_s = EPasswordReset[language]) !== null && _s !== void 0 ? _s : 'Password Reset'}</h1>
        <form action="/api/users/reset/${token}?lang=${language}" method="post">
        <label for="newPassword">${(_t = ENewPassword[language]) !== null && _t !== void 0 ? _t : 'New password'}:</label>
        <input type="password" id="newPassword" name="newPassword" required>
        <label for="confirmPassword">${(_u = EConfirmPassword[language]) !== null && _u !== void 0 ? _u : 'Confirm Password'}:</label>
        <input type="password" id="confirmPassword" name="confirmPassword" required>
        <p>${(_v = EPasswordsDoNotMatch[language]) !== null && _v !== void 0 ? _v : 'Passwords do not match!'}</p>
        <button type="submit">${(_w = EResetPassword[language]) !== null && _w !== void 0 ? _w : 'Reset password'}</button>
      </form> 
      </div>
      </body>
    </html>
  `;
                res.send(htmlResponse);
            }
            else {
                // Handle password update logic
                // ... (update the user's password in your database)
                const saltRounds = 10;
                const hashedPassword = yield bcrypt_1.default.hash(newPassword, saltRounds);
                // user.password = hashedPassword
                // // Clear the resetToken field in the database
                // user.resetToken = undefined
                // await user
                //   .save()
                const updatedUser = yield user_1.User.findOneAndUpdate({ resetToken: token }, { $set: { password: hashedPassword, resetToken: null } }, { new: true }).exec();
                if (updatedUser) {
                    res.send(`
      <!DOCTYPE html>
      <html lang=${language}>
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
        ${(_x = ETheComediansCompanion[language]) !== null && _x !== void 0 ? _x : "The Comedian' Companion"}</title>
      </head>
      <body>
      <div>
        <h1>${EPasswordResetSuccessfully[language] || 'Password reset successfully'}</h1>
        <p>
        <a href="https://react-az.jenniina.fi">${(_y = EBackToTheApp[language]) !== null && _y !== void 0 ? _y : 'Back to the app'}</a>
        </p>
      </div>
      </body>
    </html>
    `);
                }
                else {
                    res.status(500).json({ success: false, message: 'Internal Server Error *¤' });
                }
            }
        }
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal Server Error ¤' });
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
