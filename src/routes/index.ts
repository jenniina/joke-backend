import { Router } from 'express'
import {
  getUsers,
  getUser,
  addUser,
  updateUser,
  deleteUser,
  loginUser,
  registerUser,
  logoutUser,
  checkSession,
  forgotPassword,
  resetPassword,
  resetPasswordToken,
  changePassword,
  changePasswordToken,
  verifyEmail,
  verifyEmailToken,
  forgotEmail,
  resetEmail,
  resetEmailToken,
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
  getJokesByUsername,
  deleteUserFromJoke,
} from '../controllers/jokes'

const router = Router()

router.get('/api/users', getUsers)
router.get('/api/users/:id', getUser)
router.post('/api/users', addUser)
router.put('/api/users/:id', updateUser)
router.delete('/api/users/:id', deleteUser)
router.post('/api/login', loginUser)
router.post('/api/users/register', registerUser)
router.get('/api/users/logout', logoutUser)
router.get('/api/users/session', checkSession)
router.get('/api/users/verify/:token', verifyTokenMiddleware, verifyToken)
router.post('/api/users/:id', generateToken)
router.post('/api/users/forgot', forgotPassword)
router.get('/api/users/reset/:token', resetPassword)
router.post('/api/users/reset/:token', resetPasswordToken)
router.post('/api/users/change', changePassword)
router.post('/api/users/change/:token', changePasswordToken)
router.post('/api/users/verify', verifyEmail)
router.get('/api/users/verify/:token', verifyEmailToken)
router.post('/api/users/forgot', forgotEmail)
router.get('/api/users/reset/:token', resetEmail)
router.post('/api/users/reset/:token', resetEmailToken)
router.post('/api/users/change', changeEmail)
router.post('/api/users/change/:token', changeEmailToken)
router.post('/api/users/verify', verifyUsername)
router.get('/api/users/verify/:token', verifyUsernameToken)
router.post('/api/users/forgot', forgotUsername)
router.get('/api/users/reset/:token', resetUsername)
router.post('/api/users/reset/:token', resetUsernameToken)
router.post('/api/users/change', changeUsername)
router.post('/api/users/change/:token', changeUsernameToken)
router.get('/api/users/username/:username', findUserByUsername)
// router.post('/api/users/:id/delete', deleteAllJokesByUserId)

router.get('/api/users/:username/jokes', getJokesByUsername)
router.get('/api/users/:id/categories/:category/jokes', getJokesByUserAndCategory)
router.get('/api/users/:id/joketypes/:type/jokes', getJokesByUserAndType)
router.get('/api/users/:id/safe/:safe/jokes', getJokesByUserAndSafe)
// router.put('/api/users/:id/update-jokes', updateUserJokes)

router.get(
  '/api/jokes/:jokeId/:language/:category/:type',
  findJokeByJokeIdLanguageCategoryType
)
router.post('/api/jokes', addJoke)
router.put('/api/jokes/:id', updateJoke)
router.get('/api/jokes', getJokes)
router.get('/api/jokes/user/:id/', getJokesByUserId)
router.delete('/api/jokes/:id/delete-user/:userId', deleteUserFromJoke)

router.get('/api/', (req, res) => {
  res.send('Nothing to see here')
})

export default router
