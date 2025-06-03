import { Schema, model } from "mongoose";

const productModel = new Schema({
  name: { type: String, required: true },

  description: { type: String, required: true },

  price: { type: Number, required: true },

  manufacturer: {
    type: Schema.Types.ObjectId,
    required: true,
    ref: "Manufacturer",
  },
  url: { type: String, required: true },
});

export default model("Product", productModel);
