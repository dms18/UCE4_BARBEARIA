import express, { request } from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";



mongoose.connect('mongodb+srv://ADM:admin@uce.as0fkh3.mongodb.net/seuNomeDeBaseDeDados?retryWrites=true&w=majority', {
});

const app = express();
app.use(express.json());

const TOKEN = "cf4cd26e-2b4c-4196-8cd1-b39d3f5b4b5a";

app.get("/", (request, response) => {
  return response.json({ message: "Servidor funcionando!" });
});

app.post("/register", async (request, response) => {
  const body = request.body;

  if (!body.email) {
    return response.status(400).json({ message: "O e-mail é obrigatorio" });
  } else if (!body.name) {
    return response.status(400).json({ message: "O nome é obrigatorio" });
  } else if (!body.password) {
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

// teste
// temfaisfsoadfmos

app.listen(3333, () => console.log("Server running in http://localhost:3333"));

function validarID(id){
  var checkForHexRegExp = new RegExp("^[0-9a-fA-F]{24}$");
  return checkForHexRegExp.test(id);
}

