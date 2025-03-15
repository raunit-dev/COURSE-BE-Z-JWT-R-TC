const { Router } = require("express");
const { userModel, purchaseModel, courseModel } = require("../db");
const jwt = require("jsonwebtoken");
const { JWT_USER_PASSWORD } = require("../config");
const { userMiddleware } = require("../middleware/user");
const { z } = require("zod");
const bcrypt = require("bcrypt");

const userRouter = Router();

const signupSchema = z.object({
    email: z.string().email(),
    password: z
        .string()
        .min(8)
        .max(50)
        .refine(
            (password) => {
                const hasUpperCase = /[A-Z]/.test(password);
                const hasLowerCase = /[a-z]/.test(password);
                const hasNumber = /[0-9]/.test(password);
                const hasSpecialChar = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]/.test(password);

                return hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
            },
            {
                message:
                    "Password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one number, and one special character.",
            }
        ),
    firstName: z.string().min(3).max(50),
    lastName: z.string().min(3).max(50),
});

userRouter.post("/signup", async function (req, res) {
    try {
        const parsed = signupSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({
                message: "Incorrect inputs",
                errors: parsed.error,
            });
        }

        const { email, password, firstName, lastName } = parsed.data;

        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res
                .status(400)
                .json({ message: "User with this email already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await userModel.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
        });

        const token = jwt.sign({ id: user._id }, JWT_USER_PASSWORD);

        res.json({
            message: "Signup succeeded",
            token,
        });
    } catch (e) {
        console.error("Signup error:", e);
        res.status(500).json({
            message: "Error while signing up",
            error: e.message,
        });
    }
});

const signinSchema = z.object({
    email: z.string().email(),
    password: z
        .string()
        .min(8)
        .max(50)
        .refine(
            (password) => {
                const hasUpperCase = /[A-Z]/.test(password);
                const hasLowerCase = /[a-z]/.test(password);
                const hasNumber = /[0-9]/.test(password);
                const hasSpecialChar = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]/.test(password);

                return hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
            },
            {
                message:
                    "Password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one number, and one special character.",
            }
        ),
});

userRouter.post("/signin", async function (req, res) {
    try {
        const parsed = signinSchema.safeParse(req.body);

        if (!parsed.success) {
            return res.status(400).json({
                message: "Incorrect inputs",
                errors: parsed.error,
            });
        }
        const { email, password } = parsed.data;

        const user = await userModel.findOne({ email });

        if (user) {
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {
                const token = jwt.sign({ id: user._id }, JWT_USER_PASSWORD);
                return res.json({
                    token,
                });
            } else {
                return res.status(403).json({
                    message: "Incorrect credentials",
                });
            }
        } else {
            return res.status(403).json({
                message: "Incorrect credentials",
            });
        }
    } catch (e) {
        console.error("Signin error:", e);
        res.status(500).json({
            message: "Error while signing in",
            error: e.message,
        });
    }
});

userRouter.get("/purchases", userMiddleware, async function (req, res) {
    try {
        const userId = req.userId;

        const purchases = await purchaseModel.find({
            userId,
        });

        let purchasedCourseIds = [];

        for (let i = 0; i < purchases.length; i++) {
            purchasedCourseIds.push(purchases[i].courseId);
        }

        const coursesData = await courseModel.find({
            _id: { $in: purchasedCourseIds },
        });

        res.json({
            purchases,
            coursesData,
        });
    } catch (e) {
        console.error("Purchases error:", e);
        res.status(500).json({
            message: "Error while getting purchases",
            error: e.message,
        });
    }
});

module.exports = {
    userRouter: userRouter,
};
