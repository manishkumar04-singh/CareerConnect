const {ObjectId}= require("mongodb");

function validateObjectId(req,res,next){
    if(!ObjectId.isValid(req.params.id)){
        return res.status(400).render("errors/404")  
    }
    next();
}

module.exports=validateObjectId;