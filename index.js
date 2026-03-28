import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { rateLimit } from "express-rate-limit";

import UserSchema from "./schemas/User.js";
import ManufacturerSchema from "./schemas/Manufacturer.js";
import Product from "./schemas/Product.js";

const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3333;

if (!MONGO_URI || !JWT_SECRET) {
  console.error("Erro: as variáveis de ambiente MONGO_URI e JWT_SECRET são obrigatórias.");
  process.exit(1);
}

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB conectado com sucesso"))
  .catch((err) => {
    console.error("Erro ao conectar ao MongoDB:", err.message);
    process.exit(1);
  });

const app = express();
app.use(express.json());

// ── Rate limiting ──────────────────────────────────────────────────────────────

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  message: { message: "Muitas tentativas. Tente novamente em 15 minutos." },
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  message: { message: "Muitas requisições. Tente novamente em 15 minutos." },
});

// ── Utilitários ────────────────────────────────────────────────────────────────

function validarId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

// ── Middleware de autenticação ─────────────────────────────────────────────────

function autenticar(request, response, next) {
  const authHeader = request.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return response.status(401).json({ message: "Token não fornecido" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    request.userId = payload.id;
    next();
  } catch {
    return response.status(401).json({ message: "Token inválido ou expirado" });
  }
}

// ── Rotas públicas ─────────────────────────────────────────────────────────────

app.get("/", (request, response) => {
  return response.json({ message: "Servidor funcionando!" });
});

app.post("/register", authLimiter, async (request, response) => {
  const { name, celular, email, cpf, endereco, password } = request.body;

  if (!name) return response.status(400).json({ message: "O nome é obrigatório" });
  if (!celular) return response.status(400).json({ message: "O celular é obrigatório" });
  if (!email) return response.status(400).json({ message: "O e-mail é obrigatório" });
  if (!cpf) return response.status(400).json({ message: "O CPF é obrigatório" });
  if (!endereco) return response.status(400).json({ message: "O endereço é obrigatório" });
  if (!password) return response.status(400).json({ message: "A senha é obrigatória" });

  try {
    const emailExists = await UserSchema.findOne({ email });

    if (emailExists) {
      return response.status(400).json({ message: "Esse e-mail já está sendo utilizado!" });
    }

    const hash = bcrypt.hashSync(password, 10);

    const user = await UserSchema.create({ name, email, password: hash, endereco, celular, cpf });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    return response.status(201).json({ message: "Usuário criado com sucesso!", token, name });
  } catch (error) {
    return response.status(500).json({ message: "Erro ao cadastrar o usuário", error: error.message });
  }
});

app.post("/login", authLimiter, async (request, response) => {
  const { email, password } = request.body;

  if (!email || !password) {
    return response.status(400).json({ message: "E-mail e/ou senha são obrigatório(s)" });
  }

  try {
    const user = await UserSchema.findOne({ email });

    if (!user) {
      return response.status(404).json({ message: "E-mail não encontrado" });
    }

    const isCorrectPassword = bcrypt.compareSync(password, user.password);

    if (!isCorrectPassword) {
      return response.status(400).json({ message: "Senha inválida" });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    return response.status(200).json({ usuario: user.name, email: user.email, token });
  } catch (error) {
    return response.status(500).json({ message: "Erro interno: " + error.message });
  }
});

// ── Rotas protegidas – Fabricantes ─────────────────────────────────────────────

app.post("/manufacturer", apiLimiter, autenticar, async (request, response) => {
  const { name } = request.body;

  if (!name) {
    return response.status(400).json({ message: "O nome é obrigatório" });
  }

  try {
    const manufacturerCreated = await ManufacturerSchema.create({ name });
    return response.status(201).json(manufacturerCreated);
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error.message}` });
  }
});

app.get("/manufacturer", apiLimiter, autenticar, async (request, response) => {
  try {
    const manufacturers = await ManufacturerSchema.find();
    return response.json(manufacturers);
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error.message}` });
  }
});

app.put("/manufacturer/:id", apiLimiter, autenticar, async (request, response) => {
  const { id } = request.params;
  const { name } = request.body;

  if (!validarId(id)) {
    return response.status(400).json({ message: "ID inválido" });
  }

  if (!name) {
    return response.status(400).json({ message: "O nome é obrigatório" });
  }

  try {
    const updated = await ManufacturerSchema.findByIdAndUpdate(id, { name }, { new: true });

    if (!updated) {
      return response.status(404).json({ message: "Fabricante não encontrado" });
    }

    return response.status(200).json({ message: "Fabricante atualizado com sucesso" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error.message}` });
  }
});

app.delete("/manufacturer/:id", apiLimiter, autenticar, async (request, response) => {
  const { id } = request.params;

  if (!validarId(id)) {
    return response.status(400).json({ message: "ID inválido" });
  }

  try {
    const deleted = await ManufacturerSchema.findByIdAndDelete(id);

    if (!deleted) {
      return response.status(404).json({ message: "Fabricante não encontrado" });
    }

    return response.status(200).json({ message: "Fabricante removido com sucesso" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error.message}` });
  }
});

// ── Rotas protegidas – Produtos ────────────────────────────────────────────────

app.post("/product", apiLimiter, autenticar, async (request, response) => {
  const { name, description, price, manufacturer, url } = request.body;

  if (!name) return response.status(400).json({ message: "O nome é obrigatório" });
  if (!description) return response.status(400).json({ message: "A descrição é obrigatória" });
  if (price == null) return response.status(400).json({ message: "O preço é obrigatório" });
  if (!manufacturer) return response.status(400).json({ message: "O fabricante é obrigatório" });
  if (!url) return response.status(400).json({ message: "A URL é obrigatória" });

  if (!validarId(manufacturer)) {
    return response.status(400).json({ message: "ID do fabricante inválido" });
  }

  try {
    const manufacturerExists = await ManufacturerSchema.findById(manufacturer);

    if (!manufacturerExists) {
      return response.status(404).json({ message: "Fabricante não encontrado" });
    }

    await Product.create({ name, description, price, manufacturer, url });

    return response.status(201).json({ message: "Produto criado com sucesso" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error.message}` });
  }
});

app.get("/product", apiLimiter, autenticar, async (request, response) => {
  try {
    const products = await Product.find().populate("manufacturer");
    return response.json(products);
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error.message}` });
  }
});

app.get("/product/:id", apiLimiter, autenticar, async (request, response) => {
  const { id } = request.params;

  if (!validarId(id)) {
    return response.status(400).json({ message: "ID inválido" });
  }

  try {
    const product = await Product.findById(id).populate("manufacturer");

    if (!product) {
      return response.status(404).json({ message: "Produto não encontrado" });
    }

    return response.json(product);
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error.message}` });
  }
});

app.put("/product/:id", apiLimiter, autenticar, async (request, response) => {
  const { id } = request.params;
  const { name, description, price, manufacturer, url } = request.body;

  if (!validarId(id)) {
    return response.status(400).json({ message: "ID do produto inválido" });
  }

  if (manufacturer && !validarId(manufacturer)) {
    return response.status(400).json({ message: "ID do fabricante inválido" });
  }

  try {
    if (manufacturer) {
      const manufacturerExists = await ManufacturerSchema.findById(manufacturer);
      if (!manufacturerExists) {
        return response.status(400).json({ message: "Fabricante inexistente" });
      }
    }

    const updated = await Product.findByIdAndUpdate(
      id,
      { name, description, price, manufacturer, url },
      { new: true }
    );

    if (!updated) {
      return response.status(404).json({ message: "Produto não encontrado" });
    }

    return response.json({ message: "Produto atualizado com sucesso!" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error.message}` });
  }
});

app.delete("/product/:id", apiLimiter, autenticar, async (request, response) => {
  const { id } = request.params;

  if (!validarId(id)) {
    return response.status(400).json({ message: "ID inválido" });
  }

  try {
    const deleted = await Product.findByIdAndDelete(id);

    if (!deleted) {
      return response.status(404).json({ message: "Produto não encontrado" });
    }

    return response.json({ message: "Produto removido com sucesso!" });
  } catch (error) {
    return response.status(500).json({ message: `Erro no servidor: ${error.message}` });
  }
});

app.listen(PORT, () => console.log(`Server running in http://localhost:${PORT}`));
