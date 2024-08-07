import { Request, Response } from "express";
import { prismaClient } from "..";
import { hashSync, compareSync } from "bcrypt";
import * as jwt from "jsonwebtoken";
import { JWT_SECRET } from "../secrets";
export const login = async (req: Request, res: Response) => {
  const { password, email } = req.body;

  let user = await prismaClient.user.findFirst({ where: { email } });
  if (!user) {
    throw Error("User doesn't exists");
  }
  if (!compareSync(password, user.password)) {
    throw Error("Incorrect Password");
  }
  const token = jwt.sign(
    {
      userId: user.id,
    },
    JWT_SECRET
  );

  res.json({user,token})
};

export const signup = async (req: Request, res: Response) => {
  const { name, password, email } = req.body;

  let user = await prismaClient.user.findFirst({ where: { email } });
  if (user) {
    throw Error("User already exists");
  }
  user = await prismaClient.user.create({
    data: { name, email, password: hashSync(password, 10) },
  });

  res.json(user);
};
