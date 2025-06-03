import { Schema, model } from "mongoose";

const manufacturerModel = new Schema({
  name: {
    type: String,
    required: true,
  },
});

export default model("Manufacturer", manufacturerModel);
