import e from 'express'
import { IJokeSingle, IJokeTwoPart } from '../types'
import { model, Schema } from 'mongoose'

const jokeSchema: Schema = new Schema(
  {
    jokeId: {
      type: Number,
      required: true,
      unique: false,
    },
    type: {
      type: String,
      required: true,
      enum: ['single', 'twopart'],
    },
    category: {
      type: String,
      required: true,
      enum: ['Any', 'Misc', 'Programming', 'Dark', 'Pun', 'Spooky', 'Christmas'],
    },
    language: {
      type: String,
      required: true,
      enum: ['en', 'es', 'fr', 'de', 'pt', 'cs'],
    },
    safe: {
      type: Boolean,
      required: true,
    },
    user: [
      {
        type: Schema.Types.ObjectId,
        required: true,
        ref: 'User',
      },
    ],
    setup: {
      type: String,
    },
    delivery: {
      type: String,
    },
    joke: {
      type: String,
    },
  },
  { timestamps: true }
)

export const Joke = model('Joke', jokeSchema)

// const jokeSchema: Schema = new Schema(
//   {
//     jokeId: {
//       type: Number,
//       required: true,
//       unique: true,
//     },
//     type: {
//       type: String,
//       required: true,
//       enum: ['single', 'twopart'],
//     },
//     category: {
//       type: String,
//       required: true,
//       enum: ['Any', 'Misc', 'Programming', 'Dark', 'Pun', 'Spooky', 'Christmas'],
//     },
//     language: {
//       type: String,
//       required: true,
//       enum: ['en', 'es', 'fr', 'de', 'pt', 'cs'],
//     },
//     safe: {
//       type: Boolean,
//       required: true,
//     },
//     user: [
//       {
//         type: Schema.Types.ObjectId,
//         required: true,
//         ref: 'User',
//       },
//     ],
//   },
//   { timestamps: true }
// )

// export const Joke = model('Joke', jokeSchema)

// const jokeSingleSchema: Schema = new Schema(
//   {
//     joke: {
//       type: String,
//       required: true,
//     },
//     ...jokeSchema.obj,
//   },
//   { timestamps: true }
// ) as Schema<IJokeSingle>

// export const JokeSingle = Joke.discriminator('JokeSingle', jokeSingleSchema)

// const jokeTwoPartSchema: Schema = new Schema(
//   {
//     setup: {
//       type: String,
//       required: true,
//     },
//     delivery: {
//       type: String,
//       required: true,
//     },
//     ...jokeSchema.obj,
//   },
//   { timestamps: true }
// ) as Schema<IJokeTwoPart>

// export const JokeTwoPart = Joke.discriminator('JokeTwoPart', jokeTwoPartSchema)
