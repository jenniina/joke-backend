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
exports.findUserByUsername = exports.verifyToken = exports.verifyTokenMiddleware = exports.generateToken = exports.changeUsernameToken = exports.changeUsername = exports.resetUsernameToken = exports.resetUsername = exports.forgotUsername = exports.verifyUsernameToken = exports.verifyUsername = exports.changeEmailToken = exports.changeEmail = exports.resetEmailToken = exports.resetEmail = exports.forgotEmail = exports.verifyEmailToken = exports.verifyEmail = exports.changePasswordToken = exports.changePassword = exports.resetPasswordToken = exports.resetPassword = exports.forgotPassword = exports.checkSession = exports.logoutUser = exports.registerUser = exports.loginUser = exports.deleteUser = exports.updateUser = exports.addUser = exports.getUser = exports.getUsers = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const user_1 = require("../../models/user");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const generateToken = (userId) => {
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
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.verifyTokenMiddleware = verifyTokenMiddleware;
const getUsers = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const users = yield user_1.User.find();
        res.status(200).json({ users });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
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
        res.status(500).json({ message: 'An error occurred' });
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
        res.status(500).json({ message: 'An error occurred' });
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
        res.status(500).json({ success: false, message: 'An error occurred' });
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
//     res.status(500).json({ message: 'An error occurred' })
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
        res.status(500).json({ message: 'An error occurred' });
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
    try {
        const { username, password } = req.body;
        const user = yield user_1.User.findOne({ username });
        if (!user) {
            res.status(401).json({ message: 'User not found' });
        }
        else if (!user.verified) {
            res.status(401).json({ message: 'User not verified. Please check your email' });
        }
        else {
            const passwordMatch = yield comparePassword.call(user, password);
            if (passwordMatch) {
                res.status(200).json({ user });
            }
            else {
                res.status(401).json({ message: 'Invalid login credentials' });
            }
        }
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
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
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }
const registerUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { username, password, jokes, language } = req.body;
        const saltRounds = 10;
        const hashedPassword = yield bcrypt_1.default.hash(password, saltRounds);
        const user = yield user_1.User.findOne({ username });
        if (user) {
            res.status(401).json({ message: 'User already exists' });
        }
        else {
            const newUser = new user_1.User({
                username,
                password: hashedPassword,
                jokes,
                language,
                verified: false,
            });
            yield newUser.save();
            res.status(201).json({
                message: 'User registered. Please check your email for the verification link',
            });
        }
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.registerUser = registerUser;
const findUserByUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const userByUsername = yield user_1.User.findOne({
            username: req.params.username,
        });
        res.status(200).json({ user: userByUsername });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
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
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.logoutUser = logoutUser;
const checkSession = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Session checked' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.checkSession = checkSession;
const forgotPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password forgot' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.forgotPassword = forgotPassword;
const resetPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password reset' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.resetPassword = resetPassword;
const resetPasswordToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password reset with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.resetPasswordToken = resetPasswordToken;
const changePassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password changed' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.changePassword = changePassword;
const changePasswordToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Password changed with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.changePasswordToken = changePasswordToken;
const verifyEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email verified' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.verifyEmail = verifyEmail;
const verifyEmailToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email verified with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.verifyEmailToken = verifyEmailToken;
const forgotEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email forgot' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.forgotEmail = forgotEmail;
const resetEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email reset' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.resetEmail = resetEmail;
const resetEmailToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email reset with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.resetEmailToken = resetEmailToken;
const changeEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email changed' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.changeEmail = changeEmail;
const changeEmailToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Email changed with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.changeEmailToken = changeEmailToken;
const verifyUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username verified' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.verifyUsername = verifyUsername;
const verifyUsernameToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username verified with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.verifyUsernameToken = verifyUsernameToken;
const forgotUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username forgot' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.forgotUsername = forgotUsername;
const resetUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username reset' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.resetUsername = resetUsername;
const resetUsernameToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username reset with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.resetUsernameToken = resetUsernameToken;
const changeUsername = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username changed' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.changeUsername = changeUsername;
const changeUsernameToken = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        res.status(200).json({ message: 'Username changed with token' });
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});
exports.changeUsernameToken = changeUsernameToken;
