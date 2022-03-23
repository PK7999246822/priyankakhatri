const jwt = require("jsonwebtoken")
const blogModel = require("../models/blogModel")

const authentication = async function ( req , res , next ) {
    let isToken = req.headers["x-auth-token"]
    if ( !isToken ) {
        res.send({ status: false, msg: "token must be present" });
    }
 
    let decodedToken = jwt.verify(isToken, "secuiretyKeyToCheckToken");
    if ( !decodedToken ) {
        res.send({ status: false, msg: "token is invalid" });
    }

    next();

}

const authorization = async function (req, res, next) {
    try {
        let token = req.headers["x-api-key"];
        let decodedtoken = jwt.verify(token, "secuiretyKeyToCheckToken")

        let blogId = req.params.blogId
        if ( blogId ) {
            let authorId = await blogModel.find({ _id: blogId }).select({ authorId: 1, _id: 0 })
            authorId = authorId.map(x => x.authorId)

            if (decodedtoken.authorId != authorId) return res.status(403).send({ status: false, msg: "You haven't right to perform this task" })
        }
        else {
            let authorId = req.query.authorId
            if ( !authorId )  return res.status(400).send({error : "Please, enter authorId"})
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
