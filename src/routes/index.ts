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
  verificationSuccess,
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

router.get('/api/users', [authenticateUser, checkIfAdmin, getUsers])
router.get('/api/users/:id', [authenticateUser, getUser])
//router.post('/api/users', addUser)
router.put('/api/users/:id', [authenticateUser, updateUser])
router.delete('/api/users/:id', [authenticateUser, deleteUser])
router.post('/api/login', loginUser)
router.post('/api/users/register', registerUser)
router.get('/api/users/verify/:token', verifyEmailToken)
router.get('/api/users/logout', logoutUser)
router.get('/api/users/session', checkSession)
//router.get('/api/users/verify/:token', [verifyTokenMiddleware, verifyEmailToken])
router.post('/api/users/:id', generateToken)
router.post('/api/users/forgot', forgotPassword)
router.get('/api/users/reset/:token', resetPassword)
router.post('/api/users/reset/:token', resetPasswordToken)
router.post('/api/users/change', changePassword)
router.post('/api/users/change/:token', changePasswordToken)
router.post('/api/users/verify', verifyEmail)
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

router.get('/verification-success', verificationSuccess)

export default router
