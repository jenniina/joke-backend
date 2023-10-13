"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const users_1 = require("../controllers/users");
const jokes_1 = require("../controllers/jokes");
const router = (0, express_1.Router)();
router.post('/api/login', users_1.loginUser);
router.get('/api/users', [users_1.authenticateUser, users_1.checkIfAdmin, users_1.getUsers]);
router.get('/api/users/:id', users_1.getUser);
//router.post('/api/users', addUser)
router.put('/api/users/:id', [users_1.authenticateUser, users_1.updateUser]);
router.delete('/api/users/:id', [users_1.authenticateUser, users_1.deleteUser]);
router.post('/api/users/register', users_1.registerUser);
router.get('/api/users/verify/:token', users_1.verifyEmailToken);
router.get('/api/users/logout', users_1.logoutUser);
router.get('/api/users/session', users_1.checkSession);
//router.get('/api/users/verify/:token', [verifyTokenMiddleware, verifyEmailToken])
router.post('/api/users/:id', users_1.generateToken);
router.post('/api/users/forgot', users_1.forgotPassword);
router.get('/api/users/reset/:token', users_1.resetPassword);
router.post('/api/users/reset/:token', users_1.resetPasswordToken);
router.post('/api/users/change', users_1.changePassword);
router.post('/api/users/change/:token', users_1.changePasswordToken);
router.post('/api/users/verify', users_1.verifyEmail);
router.post('/api/users/change', users_1.changeEmail);
router.post('/api/users/change/:token', users_1.changeEmailToken);
router.post('/api/users/verify', users_1.verifyUsername);
router.get('/api/users/verify/:token', users_1.verifyUsernameToken);
router.post('/api/users/forgot', users_1.forgotUsername);
router.get('/api/users/reset/:token', users_1.resetUsername);
router.post('/api/users/reset/:token', users_1.resetUsernameToken);
router.post('/api/users/change', users_1.changeUsername);
router.post('/api/users/change/:token', users_1.changeUsernameToken);
router.get('/api/users/username/:username', users_1.findUserByUsername);
// router.post('/api/users/:id/delete', deleteAllJokesByUserId)
// router.get('/api/users/:username/jokes', getJokesByUsername)
router.get('/api/users/:id/categories/:category/jokes', jokes_1.getJokesByUserAndCategory);
router.get('/api/users/:id/joketypes/:type/jokes', jokes_1.getJokesByUserAndType);
router.get('/api/users/:id/safe/:safe/jokes', jokes_1.getJokesByUserAndSafe);
// router.put('/api/users/:id/update-jokes', updateUserJokes)
//router.put('/api/users/request-new-token', refreshExpiredToken)
router.get('/api/jokes/:jokeId/:language/:category/:type', jokes_1.findJokeByJokeIdLanguageCategoryType);
router.post('/api/jokes', jokes_1.addJoke);
router.put('/api/jokes/:id', jokes_1.updateJoke);
router.get('/api/jokes', jokes_1.getJokes);
router.get('/api/jokes/user/:id/', jokes_1.getJokesByUserId);
router.delete('/api/jokes/:id/delete-user/:userId', jokes_1.deleteUserFromJoke);
router.get('/api/', (req, res) => {
    res.send('Nothing to see here');
});
//router.get('/api/users/verification-success', verificationSuccess)
exports.default = router;
