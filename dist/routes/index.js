"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const users_1 = require("../controllers/users");
const jokes_1 = require("../controllers/jokes");
const quiz_1 = require("../controllers/quiz");
const router = (0, express_1.Router)();
router.get('/api/users', users_1.getUsers);
router.get('/api/users/:id', users_1.getUser);
router.post('/api/users', users_1.addUser);
router.put('/api/users/:id', users_1.updateUser);
router.delete('/api/users/:id', users_1.deleteUser);
router.post('/api/login', users_1.loginUser);
router.post('/api/users/register', users_1.registerUser);
router.get('/api/users/logout', users_1.logoutUser);
router.get('/api/users/session', users_1.checkSession);
router.get('/api/users/verify/:token', users_1.verifyTokenMiddleware, users_1.verifyToken);
router.post('/api/users/:id', users_1.generateToken);
router.post('/api/users/forgot', users_1.forgotPassword);
router.get('/api/users/reset/:token', users_1.resetPassword);
router.post('/api/users/reset/:token', users_1.resetPasswordToken);
router.post('/api/users/change', users_1.changePassword);
router.post('/api/users/change/:token', users_1.changePasswordToken);
router.post('/api/users/verify', users_1.verifyEmail);
router.get('/api/users/verify/:token', users_1.verifyEmailToken);
router.post('/api/users/forgot', users_1.forgotEmail);
router.get('/api/users/reset/:token', users_1.resetEmail);
router.post('/api/users/reset/:token', users_1.resetEmailToken);
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
router.get('/api/users/:username/jokes', jokes_1.getJokesByUsername);
router.get('/api/users/:id/categories/:category/jokes', jokes_1.getJokesByUserAndCategory);
router.get('/api/users/:id/joketypes/:type/jokes', jokes_1.getJokesByUserAndType);
router.get('/api/users/:id/safe/:safe/jokes', jokes_1.getJokesByUserAndSafe);
// router.put('/api/users/:id/update-jokes', updateUserJokes)
router.get('/api/jokes/:jokeId/:language/:category/:type', jokes_1.findJokeByJokeIdLanguageCategoryType);
router.post('/api/jokes', jokes_1.addJoke);
router.put('/api/jokes/:id', jokes_1.updateJoke);
router.get('/api/jokes', jokes_1.getJokes);
router.get('/api/jokes/user/:id/', jokes_1.getJokesByUserId);
router.delete('/api/jokes/:id/delete-user/:userId', jokes_1.deleteUserFromJoke);
//router.get('/api/quiz', getQuizzes)
router.post('/api/quiz', quiz_1.addQuiz);
router.put('/api/quiz', quiz_1.addQuiz);
router.get('/api/quiz/:id', quiz_1.getUserQuiz);
router.delete('/api/quiz/remove/:user', quiz_1.removeOldestDuplicate);
router.get('/api/', (req, res) => {
    res.send('Nothing to see here');
});
const { body } = require('express-validator');
const { sendEmailForm, sendEmailSelect } = require('../controllers/email');
router.post('/api/send-email-form', [
    body('firstName').trim().escape(),
    body('lastName').trim().escape(),
    body('email').isEmail(),
    body('message').trim().escape(),
    body('encouragement').trim().escape(),
    body('color').trim().escape(),
    body('dark').trim().escape(),
    body('light').trim().escape(),
    body('select').trim().escape(),
    body('selectmulti').trim().escape(),
], sendEmailForm);
router.post('/api/send-email-select', [
    body('issues').trim().escape(),
    body('favoriteHero').trim().escape(),
    body('clarification').trim().escape(),
], sendEmailSelect);
exports.default = router;
