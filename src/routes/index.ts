import { Router } from 'express'
//import { body } from 'express-validator'
import {
  getQuizzes,
  addQuiz,
  getUserQuiz,
  removeOldestDuplicate,
} from '../controllers/quiz'
import {
  getTodos,
  updateAllTodos,
  addTodo,
  deleteTodo,
  editTodo,
  clearCompletedTodos,
} from '../controllers/todo'

import {
  getUsers,
  getUser,
  addUser,
  updateUser,
  deleteUser,
  loginUser,
  registerUser,
  logoutUser,
  forgotPassword,
  resetPassword,
  resetPasswordToken,
  changePassword,
  changePasswordToken,
  verifyEmail,
  verifyEmailToken,
  changeEmail,
  changeEmailToken,
  verifyUsername,
  verifyUsernameToken,
  forgotUsername,
  resetUsername,
  resetUsernameToken,
  changeUsername,
  changeUsernameToken,
  verifyToken,
  generateToken,
  verifyTokenMiddleware,
  findUserByUsername,
  checkIfAdmin,
  authenticateUser,
  //verificationSuccess,
  requestNewToken,
  refreshExpiredToken,
  comparePassword,
} from '../controllers/users'
import {
  getJokes,
  addJoke,
  updateJoke,
  // deleteAllJokesByUserId,
  getJokesByUserAndCategory,
  getJokesByUserAndType,
  getJokesByUserAndSafe,
  findJokeByJokeIdLanguageCategoryType,
  getJokesByUserId,
  // getJokesByUsername,
  deleteUserFromJoke,
} from '../controllers/jokes'

const router = Router()

router.post('/api/login', loginUser)

router.post('/api/users/forgot', forgotPassword)
router.get('/api/users/reset/:token', resetPassword)
router.post('/api/users/reset/:token', resetPasswordToken)
router.get('/api/users', [authenticateUser, checkIfAdmin, getUsers])
router.get('/api/users/:id', getUser)
//router.post('/api/users', addUser)
router.put('/api/users/:id', [comparePassword, updateUser])
router.delete('/api/users/:id', [authenticateUser, deleteUser])
router.post('/api/users/register', registerUser)
router.get('/api/users/verify/:token', verifyEmailToken)
router.get('/api/users/logout', logoutUser)
//router.get('/api/users/verify/:token', [verifyTokenMiddleware, verifyEmailToken])
router.post('/api/users/:id', generateToken)
router.post('/api/users/change', changePassword)
router.post('/api/users/change/:token', changePasswordToken)
router.post('/api/users/verify', verifyEmail)
router.post('/api/users/change', changeEmail)
router.post('/api/users/change/:token', changeEmailToken)
router.post('/api/users/verify', verifyUsername)
router.get('/api/users/verify/:token', verifyUsernameToken)
//router.post('/api/users/forgot', forgotUsername)
router.get('/api/users/reset/:token', resetUsername)
router.post('/api/users/reset/:token', resetUsernameToken)
router.post('/api/users/change', changeUsername)
router.post('/api/users/change/:token', changeUsernameToken)
router.get('/api/users/username/:username', findUserByUsername)
// router.post('/api/users/:id/delete', deleteAllJokesByUserId)

// router.get('/api/users/:username/jokes', getJokesByUsername)
router.get('/api/users/:id/categories/:category/jokes', getJokesByUserAndCategory)
router.get('/api/users/:id/joketypes/:type/jokes', getJokesByUserAndType)
router.get('/api/users/:id/safe/:safe/jokes', getJokesByUserAndSafe)
// router.put('/api/users/:id/update-jokes', updateUserJokes)

//router.put('/api/users/request-new-token', refreshExpiredToken)

router.get(
  '/api/jokes/:jokeId/:language/:category/:type',
  findJokeByJokeIdLanguageCategoryType
)
router.post('/api/jokes', addJoke)
router.put('/api/jokes/:id', updateJoke)
router.get('/api/jokes', getJokes)
router.get('/api/jokes/user/:id/', getJokesByUserId)
router.delete('/api/jokes/:id/delete-user/:userId', deleteUserFromJoke)

//router.get('/api/quiz', getQuizzes)
router.post('/api/quiz', addQuiz)
router.put('/api/quiz', addQuiz)
router.get('/api/quiz/:id', getUserQuiz)
router.delete('/api/quiz/remove/:user', removeOldestDuplicate)

router.get('/api/todo/:user', getTodos)
router.put('/api/todo/:user', updateAllTodos)
router.post('/api/todo/:user', addTodo)
router.delete('/api/todo/:user/:key', deleteTodo)
router.put('/api/todo/:user/:key', editTodo)
router.delete('/api/todo/:user', clearCompletedTodos)

router.get('/api/', (req, res) => {
  res.send('Nothing to see here')
})

const { body } = require('express-validator')
const { sendEmailForm, sendEmailSelect } = require('../controllers/email')

router.post(
  '/api/send-email-form',
  [
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
  ],
  sendEmailForm
)

router.post(
  '/api/send-email-select',
  [
    body('issues').trim().escape(),
    body('favoriteHero').trim().escape(),
    body('clarification').trim().escape(),
  ],
  sendEmailSelect
)

export default router
