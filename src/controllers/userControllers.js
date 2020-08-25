import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { UserSchema } from "../models/userModel";

const User = mongoose.model("User", UserSchema);

export const loginRequired = (req, res, next) => {
    if (req.user) { // If we have a logged in user
        next(); // GET, POST, DELETE etc.
    } else {
        return res.status(401).json({ message: "Unauthorised user!" };)
    }
};