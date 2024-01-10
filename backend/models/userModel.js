import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    emp_id: {
      type: Number,
      required: true,
      unique: true,
    },
    emp_code: {
      type: Number,
      required: true,
      unique: true,
    },
    emp_role: {
      type: String,
      required: true,
    },
    emp_gender: {
      type: String,
      required: true,
    },
    emp_birthday: {
      type: String,
      required: true,
    },
    em_joining_date: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

// Match user entered password to hashed password in database
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Encrypt password using bcrypt
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

const User = mongoose.model('User', userSchema);

export default User;
