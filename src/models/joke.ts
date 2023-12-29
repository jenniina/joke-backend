import { model, Schema } from 'mongoose'

const jokeSchema: Schema = new Schema(
  {
    jokeId: {
      type: String,
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
      // enum: ['Any', 'Misc', 'Programming', 'Dark', 'Pun', 'Spooky', 'Christmas'],
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
