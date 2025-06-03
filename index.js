import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";

import UserSchema from "./schemas/User.js";
import ManufacturerSchema from "./schemas/Manufacturer.js";
import Product from "./schemas/Product.js";

mongoose.connect(
  "mongodb+srv://admin:admin@cluster0.r4oahr4.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
);

const app = express();
app.use(express.json());

const TOKEN = "cf4cd26e-2b4c-4196-8cd1-b39d3f5b4b5a";

app.get("/", (request, response) => {
  return response.json({ message: "Servidor funcionando!" });
});

app.post("/register", async (request, response) => {
  const body = request.body;

  if (!body.name) {
    return response.status(400).json({ message: "O nome e obrigatorio" });
  } else if (!body.celular) {
    return response.status(400).json({ message: "O celular e obrigatorio" });
  } else if (!body.email) {
    return response.status(400).json({ message: "O email e obrigatorio" });
  }else if (!body.cpf) {
    return response.status(400).json({ message: "O cpf e obrigatorio" });
  }else if (!body.endereco) {
    return response.status(400).json({ message: "O endereco e obrigatorio" });
  }else if (!body.password) {
    return response.status(400).json({ message: "A senha é obrigatoria" });
  }

  const emailExists = await UserSchema.findOne({ email: body.email });

  if (emailExists) {
    return response
      .status(400)
      .json({ message: "Esse e-mail ja esta sendo utilizado!" });
  }

  const hash = bcrypt.hashSync(request.body.password, 8);

  try {
    await UserSchema.create({
      email: body.email,
      name: body.name,
      password: hash,
      endereco: body.endereco,
      celular: body.celular,
      cpf: body.cpf
    });

    return response.status(201).json({
      message: "Usuario criado com sucesso!",
      token: TOKEN,
      name: body.name,
    });
  } catch (error) {
    return response.status(500).json({
      message: "Erro ao cadastrar o usuário",
      error: error,
    });
  }
});

app.post("/login", async (request, response) => {
  const body = request.body;

  try {
    if (!body.email || !body.password) {
      return response
        .status(400)
        .json({ message: "E-mail e/ou senha são obrigatório(s)" });
    }

    const userExists = await UserSchema.findOne({ email: body.email });

    if (!userExists) {
      return response.status(404).json({ message: "E-mail não encontrado" });
    }

    const isCorrectPassword = bcrypt.compareSync(
      body.password,
      userExists.password
    );

    if (!isCorrectPassword) {
      return response.status(400).json({ message: "Senha inválida" });
    }

    return response.status(200).json({
      usuario: userExists.name,
      email: userExists.email,
      token: TOKEN,
    });
  } catch (error) {
    return response.status(500).json({
      message: "Erro interno: " + error,
    });
  }
});

app.post("/manufacturer", async (request, response) => {
  const body = request.body;

  if (!body.name) {
    return response.status(400).json({ message: "O nome é obrigatório" });
  }

  try {
    const manufacturerCreated = await ManufacturerSchema.create({
      name: body.name,
    });

    return response.status(201).json(manufacturerCreated);
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error}` });
  }
});

app.get("/manufacturer", async (request, response) => {
  try {
    const manufacturers = await ManufacturerSchema.find();
    return response.json(manufacturers);
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error}` });
  }
});

app.delete("/manufacturer/:id", async (request, response) => {
  const id = request.params.id;

  try {
    await ManufacturerSchema.findByIdAndDelete(id);
    return response
      .status(200)
      .json({ message: "Fabricante removido com sucesso" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error}` });
  }
});

app.put("/manufacturer/:id", async (request, response) => {
  const id = request.params.id;
  const body = request.body;

  try {
    await ManufacturerSchema.findByIdAndUpdate(id, { name: body.name });
    return response
      .status(200)
      .json({ message: "Fabricante atualizado com sucesso" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error}` });
  }
});

app.post("/product", async (request, response) => {
  const body = request.body;

  try {
    const manufacturerExists = await ManufacturerSchema.findById(
      body.manufacturer
    );

    if (!manufacturerExists) {
      return response
        .status(404)
        .json({ message: "Fabricante nao encontrado." });
    }

    await Product.create({
      name: body.name,
      description: body.description,
      price: body.price,
      manufacturer: body.manufacturer,
      url: body.url,
    });

    return response.status(201).json({ message: "Produto criado com sucesso" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error}` });
  }
});

app.get("/product", async (request, response) => {
  try {
    const products = await Product.find().populate("manufacturer");
    return response.json(products);
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error}` });
  }
});

app.get("/product/:id", async (request, response) => {
  const id = request.params.id;

  try {
    const products = await Product.findById(id).populate("manufacturer");
    return response.json(products);
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error}` });
  }
});

app.put("/product/:id", async (request, response) => {
  const id = request.params.id;
  const body = request.body;

  if (!validarId(body.manufacturer)) {
    return response.status(400).json({ message: "ID Inválido." });
  }

  try {
    const manufacturerExists = await ManufacturerSchema.findById(
      body?.manufacturer
    );

    if (!manufacturerExists) {
      return response.status(400).json({ message: "Fabricante inexistente." });
    }

    await Product.findByIdAndUpdate(id, {
      name: body.name,
      price: body.price,
      url: body.url,
      manufacturer: body.manufacturer,
      description: body.description,
    });

    return response.json({ message: "Produto atualizado com sucesso!" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error}` });
  }
});

app.delete("/product/:id", async (request, response) => {
  const id = request.params.id;

  if (!validarId(id)) {
    return response.status(400).json({ message: "ID Inválido" });
  }

  try {
    const productExists = await Product.findById(id);
    if (!productExists) {
      return response.status(404).json({ message: "Produto inexistente" });
    }

    await Product.findByIdAndDelete(id);
    return response.json({ message: "Produto removido com sucesso!" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error}` });
  }
});

app.listen(3333, () => console.log("Server running in http://localhost:3333"));

function validarId(id) {
  var checkForHexRegExp = new RegExp("^[0-9a-fA-F]{24}$");
  return checkForHexRegExp.test(id);
}
