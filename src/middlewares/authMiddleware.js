const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  let token;
  const authHeader = req.headers.authorization || req.headers.Authorization;

  if (authHeader && authHeader.startsWith("Bearer")) {
    token = authHeader.split(" ")[1];

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      console.log("The decoded user is:", req.user);
      next();
    } catch (err) {
      return res.status(400).json({ message: "Token is not valid" });
    }

  } else {
    return res.status(401).json({ message: "No token, authorization denied" });
  }
};

module.exports = verifyToken;
