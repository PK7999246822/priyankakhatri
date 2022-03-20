const jwt = require("jsonwebtoken")
const blogModel = require("../models/blogModel")

const authentication = function (req, res, next) {
    try {
        let token = req.headers["x-api-key"]
        if (!token) {
            return res.status(400).send({ status: false, msg: "token must be present" });
        }
        let decodedToken = jwt.verify(token, "secuiretyKeyToCheckToken");
        
        if (!decodedToken) {
            return res.status(401).send({ status: false, msg: "token is invalid" });
        }
        console.log("token",decodedToken)
        next();
    }
    catch (err) {
        console.log(err)
        res.status(500).send({ msg: err.message })
    }

}


const authorization = async function (req, res, next) {
    try {
        let token = req.headers["x-api-key"];
        let decodedtoken = jwt.verify(token, "secuiretyKeyToCheckToken")

        let blogId = req.params.blogId
        if (!blogId) blogId = req.query._id

        if (blogId) {
            let authorId = await blogModel.find({ _id: blogId }).select({ authorId: 1, _id: 0 })
            authorId = authorId.map(x => x.authorId)

            if (decodedtoken.authorId != authorId) return res.status(403).send({ status: false, msg: "You haven't right to perform this task" })
        }
        else {
            let authorId = req.query.authorId
            if ( !authorId )  return res.status(400).send({error : "Please, enter authorId or blogId"})
            if (decodedtoken.authorId != authorId) return res.status(403).send({ status: false, msg: "You haven't right to perform this task" })
        }
        next()
    }
    catch (error) {
        console.log(error)
        res.status(500).send({ msg: error.message })
    }
}


module.exports.authorization = authorization
module.exports.authentication = authentication
