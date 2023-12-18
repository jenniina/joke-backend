import { Todo } from '../../models/todo'
import { Response, Request } from 'express'
import { ITodo, ITodos } from '../../types'

const getTodos = async (req: Request, res: Response) => {
  try {
    const { user } = req.params
    const todoDocument = await Todo.findOne({ user })
    if (!todoDocument) {
      const newTodo = new Todo({ user, todos: [] })
      const savedTodoDocument = await newTodo.save()
      return res.json(savedTodoDocument.todos)
    }
    res.json(todoDocument?.todos)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

const updateAllTodos = async (req: Request, res: Response) => {
  try {
    const { user } = req.params
    const newTodos: ITodo[] = req.body
    let todoDocument = await Todo.findOne({ user })
    if (!todoDocument) {
      const newTodo = new Todo({ user, todos: newTodos })
      const savedTodoDocument = await newTodo.save()
      console.log('savedTodoDocument.todos: ', savedTodoDocument.todos)
      return res.json(savedTodoDocument.todos)
    } else {
      console.log('todoDocument.todos 1: ', todoDocument.todos)
      todoDocument.todos = todoDocument.todos.map((todo: ITodo) => {
        const newTodo = newTodos.find((newTodo) => newTodo.key === todo.key)
        return newTodo ? newTodo : todo
      })
      console.log('todoDocument.todos 2: ', todoDocument.todos)
      todoDocument = await Todo.findOneAndUpdate(
        { user },
        { todos: todoDocument.todos },
        { new: true, useFindAndModify: false }
      )
      console.log('todoDocument: ', todoDocument)
      return res.json(todoDocument?.todos)
    }
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

const addTodo = async (req: Request, res: Response) => {
  try {
    const { user } = req.params
    const todoDocument = await Todo.findOne({ user })
    if (!todoDocument) {
      return res.status(404).json({ message: 'No todos found for this user' })
    }
    const { complete, name, key } = req.body
    if (complete === undefined || name === undefined || key === undefined) {
      return res
        .status(400)
        .json({ message: 'Task must include complete, name, and key fields' })
    }
    const newTodo = { complete, name, key }
    const updatedTodoDocument = await Todo.findOneAndUpdate(
      { user },
      { $push: { todos: newTodo } },
      { new: true, useFindAndModify: false }
    )
    if (!updatedTodoDocument) {
      return res.status(404).json({ message: 'No todos found for this user' })
    }
    const addedTodo = updatedTodoDocument.todos.find((todo: ITodo) => todo.key === key)
    res.json(addedTodo)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

const deleteTodo = async (req: Request, res: Response) => {
  try {
    const { user, key } = req.params
    console.log('deleteTodo user: ', user)
    const updatedTodoDocument = await Todo.findOneAndUpdate(
      { user },
      { $pull: { todos: { key: key } } },
      { new: true, useFindAndModify: false }
    )
    if (!updatedTodoDocument) {
      return res.status(404).json({ message: 'No todos found for this user' })
    }
    res.json(updatedTodoDocument)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

const clearCompletedTodos = async (req: Request, res: Response) => {
  try {
    console.log('user: ', req.params.user)
    const { user } = req.params
    //const userId = new mongoose.Types.ObjectId(user)
    const updatedTodoDocument = await Todo.findOneAndUpdate(
      { user },
      { $pull: { todos: { complete: true } } },
      { new: true, useFindAndModify: false }
    )
    console.log('updatedTodoDocument: ', updatedTodoDocument)
    if (!updatedTodoDocument) {
      return res.status(404).json({ message: 'No todos found for this user' })
    }
    res.json(updatedTodoDocument)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

const editTodo = async (req: Request, res: Response) => {
  try {
    const { user, key } = req.params
    const todoDocument = await Todo.findOneAndUpdate(
      { user, 'todos.key': key },
      { $set: { 'todos.$.complete': req.body.complete } },
      { new: true }
    )
    if (!todoDocument) {
      return res.status(404).json({ message: 'No todos found for this user' })
    }
    //return the updated todo
    const updatedTodo: ITodos = todoDocument.todos.find((todo: ITodo) => todo.key === key)
    res.json(updatedTodo)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

export { getTodos, updateAllTodos, addTodo, deleteTodo, editTodo, clearCompletedTodos }
