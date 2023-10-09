import e, { Response, Request } from 'express'
import { IJoke, EJokeType } from '../../types'
import { Joke } from '../../models/joke'

const getJokes = async (req: Request, res: Response): Promise<void> => {
  try {
    const jokes: IJoke[] = await Joke.find()
    res.status(200).json(jokes)
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' })
    console.error('Error:', error)
  }
}

const mapToJoke = (doc: any): IJoke => {
  return {
    jokeId: doc.jokeId,
    type: doc.type,
    category: doc.category,
    language: doc.language,
    safe: doc.safe,
    user: doc.user,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
    ...(doc.type === EJokeType.single
      ? { joke: doc.joke }
      : { setup: doc.setup, delivery: doc.delivery }),
  }
}

const addJoke = async (req: Request, res: Response): Promise<void> => {
  //Joke.collection.dropIndex('jokeId_1')
  try {
    const body = req.body as Pick<
      IJoke,
      'jokeId' | 'type' | 'category' | 'user' | 'language'
    >

    // Validate input fields
    if (!body.jokeId || !body.category || !body.user || !body.language) {
      res.status(400).json({ message: 'Missing required fields' })
    }

    let joke: IJoke

    // Check if a joke already exists
    const existingJoke = await (body &&
      Joke.findOne({
        jokeId: body.jokeId,
        type: body.type,
        category: body.category,
        language: body.language,
      }))

    if (existingJoke) {
      // Check if the user ID already exists in the user array
      if (!existingJoke.user.includes(req.body.user)) {
        existingJoke.user.push(req.body.user)
        await existingJoke.save()
      }
      joke = mapToJoke(existingJoke)
    } else {
      if (req.body.type === EJokeType.single) {
        const savedJoke = await new Joke({
          jokeId: body.jokeId,
          joke: req.body.joke,
          category: body.category,
          type: body.type,
          safe: req.body.safe,
          user: [body.user],
          language: body.language,
        }).save()

        joke = mapToJoke(savedJoke)
      } else {
        const savedJoke = await new Joke({
          jokeId: body.jokeId,
          setup: req.body.setup,
          delivery: req.body.delivery,
          category: body.category,
          type: body.type,
          safe: req.body.safe,
          user: [body.user],
          language: body.language,
        }).save()

        joke = mapToJoke(savedJoke)
      }
    }

    res.status(201).json({ success: true, message: 'Joke added', data: joke })
  } catch (error) {
    res.status(500).json({ success: false, message: 'An error occurred' })
    console.error('Error:', error)
  }
}

const updateJoke = async (req: Request, res: Response): Promise<void> => {
  try {
    const {
      params: { jokeId },
      body,
    } = req

    let joke: IJoke

    const updateJoke: IJoke | null = await Joke.findOneAndUpdate({ jokeId: jokeId }, body)
    joke = mapToJoke(updateJoke)

    const allJokes = await Joke.find()

    res.status(200).json({ message: 'Joke updated', joke, jokes: allJokes })
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' })
    console.error('Error:', error)
  }
}

const deleteUserFromJoke = async (req: Request, res: Response): Promise<void> => {
  try {
    const {
      params: { id: _id, userId },
    } = req

    const joke: IJoke | null = await Joke.findOne({ _id: _id })
    const userIndex = joke?.user.indexOf(userId)

    if (userIndex !== undefined && userIndex !== -1) {
      joke?.user.splice(userIndex, 1)
      await (joke as any).save()
    }
    if (joke?.user.length === 0) {
      await Joke.findOneAndDelete({ _id: _id })
    }

    res.status(200).json({ message: 'User deleted from joke', joke })
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' })
    console.error('Error:', error)
  }
}

// const deleteUserFromJokeAndDeleteJokeIfUserArrayEmpty = async (
//   req: Request,
//   res: Response
// ): Promise<void> => {
//   try {
//     const {
//       params: { id: _id, userId },
//     } = req

//     const joke: IJoke | null = await Joke.findOne({ _id: _id })
//     const userIndex = joke?.user.indexOf(userId)

//     if (userIndex !== undefined && userIndex !== -1) {
//       joke?.user.splice(userIndex, 1)
//       await joke?.save()
//     }

//     res.status(200).json({ message: 'User deleted from joke', joke })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

const findJokeByJokeIdLanguageCategoryType = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const joke: IJoke | null = await Joke.findOne({
      jokeId: req.params.jokeId,
      category: req.params.category,
      language: req.params.language,
      type: req.params.type,
    })
    res.status(200).json(joke)
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' })
    console.error('Error:', error)
  }
}

const getJokesByUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    const jokes: IJoke[] | null = await Joke.findOne({ user: req.params.username })
    res.status(200).json({ jokes })
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' })
    console.error('Error:', error)
  }
}

const getJokesByUserId = async (req: Request, res: Response): Promise<void> => {
  try {
    const jokes: IJoke[] | null = await Joke.findOne({ user: req.params.id })
    res.status(200).json({ jokes })
  } catch (error) {
    throw error
  }
}

const getJokesByUserAndCategory = async (req: Request, res: Response): Promise<void> => {
  try {
    const jokes: IJoke[] | null = await Joke.findOne({
      user: req.params.id,
      category: req.params.category,
    })
    res.status(200).json({ jokes })
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' })
    console.error('Error:', error)
  }
}

const getJokesByUserAndType = async (req: Request, res: Response): Promise<void> => {
  try {
    const jokes: IJoke[] | null = await Joke.findOne({
      user: req.params.id,
      type: req.params.type,
    })
    res.status(200).json({ jokes })
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' })
    console.error('Error:', error)
  }
}

const getJokesByUserAndSafe = async (req: Request, res: Response): Promise<void> => {
  try {
    const jokes: IJoke[] | null = await Joke.findOne({
      user: req.params.id,
      safe: req.params.safe,
    })
    res.status(200).json({ jokes })
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' })
    console.error('Error:', error)
  }
}

// const getJokesByUserAndCategory = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const jokesSingle: IJokeSingle[] = await JokeSingle.find({
//       user: req.params.id,
//       category: req.params.category,
//     })
//     const jokesTwoPart: IJokeTwoPart[] = await JokeTwoPart.find({
//       user: req.params.id,
//       category: req.params.category,
//     })
//     res.status(200).json({ jokesSingle, jokesTwoPart })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const getJokesByUserAndType = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const jokesSingle: IJokeSingle[] = await JokeSingle.find({
//       user: req.params.id,
//       type: req.params.type,
//     })
//     const jokesTwoPart: IJokeTwoPart[] = await JokeTwoPart.find({
//       user: req.params.id,
//       type: req.params.type,
//     })
//     res.status(200).json({ jokesSingle, jokesTwoPart })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const getJokesByUserAndSafe = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const jokesSingle: IJokeSingle[] = await JokeSingle.find({
//       user: req.params.id,
//       safe: req.params.safe,
//     })
//     const jokesTwoPart: IJokeTwoPart[] = await JokeTwoPart.find({
//       user: req.params.id,
//       safe: req.params.safe,
//     })
//     res.status(200).json({ jokesSingle, jokesTwoPart })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const deleteCategory = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const deletedCategory: ECategory_en | null = await Category.findByIdAndRemove(
//       req.params.id
//     )
//     const allCategories: ECategory_en = await Category.find()
//     res.status(200).json({
//       message: 'Category deleted',
//       category: deletedCategory,
//       categories: allCategories,
//     })
//   } catch (error) {
//     throw error
//   }
// }
// const getJokes = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const jokesSingle: IJokeSingle[] = await JokeSingle.find()
//     const jokesTwoPart: IJokeTwoPart[] = await JokeTwoPart.find()
//     res.status(200).json({ jokesSingle, jokesTwoPart })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// // Define a mapping function for single jokes
// function mapToSingleJoke(doc: any): IJokeSingle {
//   return {
//     jokeId: doc.jokeId,
//     joke: doc.joke,
//     category: doc.category,
//     safe: doc.safe,
//     user: doc.user,
//     language: doc.language,
//     type: EJokeType.single,
//   }
// }

// // Define a mapping function for two-part jokes
// function mapToTwoPartJoke(doc: any): IJokeTwoPart {
//   return {
//     jokeId: doc.jokeId,
//     setup: doc.setup,
//     delivery: doc.delivery,
//     category: doc.category,
//     safe: doc.safe,
//     user: doc.user,
//     language: doc.language,
//     type: EJokeType.twopart,
//   }
// }

// const addJoke = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const body = req.body as Pick<
//       IJoke,
//       'jokeId' | 'category' | 'safe' | 'user' | 'language'
//     >

//     // Validate input fields
//     if (!body.jokeId || !body.category || !body.safe || !body.user || !body.language) {
//       res.status(400).json({ message: 'Missing required fields' })
//     }

//     let joke: IJoke

//     // Check if a joke with the given jokeId already exists
//     const existingJoke = await (body.jokeId && Joke.findOne({ jokeId: body.jokeId }))

//     if (existingJoke) {
//       // // Update the existing joke
//       // if ('joke' in body) {
//       //   existingJoke.joke = body.joke
//       // } else {
//       //   existingJoke.setup = req.body.setup
//       //   existingJoke.delivery = req.body.delivery
//       // }
//       // existingJoke.category = body.category
//       // existingJoke.safe = body.safe
//       existingJoke.user.push(req.body.user)
//       // existingJoke.language = body.language

//       await existingJoke.save()

//       joke =
//         existingJoke.type === EJokeType.single
//           ? mapToSingleJoke(existingJoke)
//           : mapToTwoPartJoke(existingJoke)
//     } else {
//       if ('joke' in body) {
//         // It's a single joke
//         const savedJoke = await new JokeSingle({
//           jokeId: body.jokeId,
//           joke: req.body.joke,
//           category: body.category,
//           safe: body.safe,
//           user: [body.user],
//           language: body.language,
//         }).save()

//         joke = mapToSingleJoke(savedJoke)
//       } else {
//         // It's a two-part joke
//         const savedJoke = await new JokeTwoPart({
//           jokeId: body.jokeId,
//           setup: req.body.setup,
//           delivery: req.body.delivery,
//           category: body.category,
//           safe: body.safe,
//           user: [body.user],
//           language: body.language,
//         }).save()

//         joke = mapToTwoPartJoke(savedJoke)
//       }
//     }
//     // Fetch jokes based on the type
//     const allJokes = await (joke.type === EJokeType.single
//       ? JokeSingle.find()
//       : JokeTwoPart.find())

//     res.status(201).json({ message: 'Joke added', joke, jokes: allJokes })
//     // const allJokes = (await (joke instanceof JokeSingle
//     //   ? JokeSingle.find()
//     //   : JokeTwoPart.find())) as IJokeSingle[] | IJokeTwoPart[]

//     // res.status(201).json({ message: 'Joke added', joke: newJoke, jokes: allJokes })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const addJokeSingle = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const body = req.body as Pick<
//       IJokeSingle,
//       'jokeId' | 'joke' | 'category' | 'safe' | 'user' | 'language'
//     >

//     const joke: IJokeSingle = new JokeSingle({
//       jokeId: body.jokeId,
//       joke: body.joke,
//       category: body.category,
//       safe: body.safe,
//       user: body.user,
//       language: body.language,
//     })

//     const newJoke: IJokeSingle = await joke.save()
//     const allJokes: IJokeSingle[] = await JokeSingle.find()

//     res.status(201).json({ message: 'Joke added', joke: newJoke, jokes: allJokes })
//   } catch (error) {
//     throw error
//   }
// }

// const addJokeTwoPart = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const body = req.body as Pick<
//       IJokeTwoPart,
//       'jokeId' | 'setup' | 'delivery' | 'category' | 'safe' | 'user' | 'language'
//     >

//     const joke: IJokeTwoPart = new JokeTwoPart({
//       jokeId: body.jokeId,
//       setup: body.setup,
//       delivery: body.delivery,
//       category: body.category,
//       safe: body.safe,
//       user: body.user,
//       language: body.language,
//     })

//     const newJoke: IJokeTwoPart = await joke.save()
//     const allJokes: IJokeTwoPart[] = await JokeTwoPart.find()

//     res.status(201).json({ message: 'Joke added', joke: newJoke, jokes: allJokes })
//   } catch (error) {
//     throw error
//   }
// }

// const updateJoke = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const {
//       params: { id },
//       body,
//     } = req

//     let joke: IJoke

//     if ('joke' in body) {
//       // It's a single joke
//       const updateJoke: IJokeSingle | null = await JokeSingle.findByIdAndUpdate(
//         { _id: id },
//         body
//       )
//       joke = mapToSingleJoke(updateJoke)
//     } else {
//       // It's a two-part joke
//       const updateJoke: IJokeTwoPart | null = await JokeTwoPart.findByIdAndUpdate(
//         { _id: id },
//         body
//       )
//       joke = mapToTwoPartJoke(updateJoke)
//     }

//     const allJokes = await (joke.type === EJokeType.single
//       ? JokeSingle.find()
//       : JokeTwoPart.find())

//     res.status(200).json({ message: 'Joke updated', joke, jokes: allJokes })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const updateJokeSingle = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const {
//       params: { id },
//       body,
//     } = req
//     const updateJoke: IJokeSingle | null = await JokeSingle.findByIdAndUpdate(
//       { _id: id },
//       body
//     )
//     const allJokes: IJokeSingle[] = await JokeSingle.find()
//     res.status(200).json({
//       message: 'Joke updated',
//       joke: updateJoke,
//       jokes: allJokes,
//     })
//   } catch (error) {
//     throw error
//   }
// }

// const updateJokeTwoPart = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const {
//       params: { id },
//       body,
//     } = req
//     const updateJoke: IJokeTwoPart | null = await JokeTwoPart.findByIdAndUpdate(
//       { _id: id },
//       body
//     )
//     const allJokes: IJokeTwoPart[] = await JokeTwoPart.find()
//     res.status(200).json({
//       message: 'Joke updated',
//       joke: updateJoke,
//       jokes: allJokes,
//     })
//   } catch (error) {
//     throw error
//   }
// }

// const findJokeByJokeId = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const jokeSingle: IJokeSingle | null = await JokeSingle.findOne({
//       jokeId: req.params.jokeId,
//     })
//     const jokeTwoPart: IJokeTwoPart | null = await JokeTwoPart.findOne({
//       jokeId: req.params.jokeId,
//     })
//     res.status(200).json({ jokeSingle, jokeTwoPart })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const updateCategory = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const {
//       params: { id },
//       body,
//     } = req
//     const updateCategory: ECategory_en | null = await Category.findByIdAndUpdate(
//       { _id: id },
//       body
//     )
//     const allCategories: ECategory_en = await Category.find()
//     res.status(200).json({
//       message: 'Category updated',
//       category: updateCategory,
//       categories: allCategories,
//     })
//   } catch (error) {
//     throw error
//   }
// }

// const deleteAllJokes = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const deletedJokesSingle = await JokeSingle.deleteMany({})
//     const deletedJokesTwoPart = await JokeTwoPart.deleteMany({})
//     const allJokesSingle: IJokeSingle[] = await JokeSingle.find()
//     const allJokesTwoPart: IJokeTwoPart[] = await JokeTwoPart.find()
//     res.status(200).json({
//       message: 'Jokes deleted',
//       jokesSingle: deletedJokesSingle,
//       jokesTwoPart: deletedJokesTwoPart,
//       allJokesSingle,
//       allJokesTwoPart,
//     })
//   } catch (error) {
//     throw error
//   }
// }

// const deleteAllJokesByUserId = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const deletedJokesSingle = await JokeSingle.deleteMany({ user: req.params.id })
//     const deletedJokesTwoPart = await JokeTwoPart.deleteMany({ user: req.params.id })
//     const allJokesSingle: IJokeSingle[] = await JokeSingle.find()
//     const allJokesTwoPart: IJokeTwoPart[] = await JokeTwoPart.find()
//     res.status(200).json({
//       message: 'Jokes deleted',
//       jokesSingle: deletedJokesSingle,
//       jokesTwoPart: deletedJokesTwoPart,
//       allJokesSingle,
//       allJokesTwoPart,
//     })
//   } catch (error) {
//     throw error
//   }
// }

// const deleteJokeSingle = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const deletedJoke: IJokeSingle | null = await JokeSingle.findByIdAndRemove(
//       req.params.id
//     )
//     const allJokes: IJokeSingle[] = await JokeSingle.find()
//     res.status(200).json({
//       message: 'Joke deleted',
//       joke: deletedJoke,
//       jokes: allJokes,
//     })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const deleteJokeTwoPart = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const deletedJoke: IJokeTwoPart | null = await JokeTwoPart.findByIdAndRemove(
//       req.params.id
//     )
//     const allJokes: IJokeTwoPart[] = await JokeTwoPart.find()
//     res.status(200).json({
//       message: 'Joke deleted',
//       joke: deletedJoke,
//       jokes: allJokes,
//     })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const getJokesByUserId = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const jokesSingle: IJokeSingle[] = await JokeSingle.find({ user: req.params.id })
//     const jokesTwoPart: IJokeTwoPart[] = await JokeTwoPart.find({ user: req.params.id })
//     res.status(200).json({ jokesSingle, jokesTwoPart })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const getSingleJokesByUserId = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const jokesSingle: IJokeSingle[] = await JokeSingle.find({ user: req.params.id })
//     res.status(200).json({ jokesSingle })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

// const getTwoPartJokesByUserId = async (req: Request, res: Response): Promise<void> => {
//   try {
//     const jokesTwoPart: IJokeTwoPart[] = await JokeTwoPart.find({ user: req.params.id })
//     res.status(200).json({ jokesTwoPart })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

export {
  getJokes,
  addJoke,
  updateJoke,
  findJokeByJokeIdLanguageCategoryType,
  getJokesByUsername,
  getJokesByUserId,
  getJokesByUserAndCategory,
  getJokesByUserAndType,
  getJokesByUserAndSafe,
  deleteUserFromJoke,
}
