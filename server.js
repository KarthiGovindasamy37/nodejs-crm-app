const express=require("express")
const app=express()
const cors=require("cors")
const mongodb=require("mongodb")
const mongoclient=mongodb.MongoClient
const dotenv=require("dotenv").config()
const jwt=require("jsonwebtoken")
const nodemailer=require("nodemailer")
const random=require("randomstring")
const bcrypt=require("bcryptjs")

let URL=process.env.URL
let DB=process.env.DB
let SECRET=process.env.SECRET
let PASS=process.env.PASS
let USER=process.env.USER

app.use(express.json())
app.use(cors({
    origin : "https://super-dodol-58d830.netlify.app"
}))


let sendEmail=async(res,temp,mail)=>{
    try {
        
        let transporter=nodemailer.createTransport({
            host:"smtp.gmail.com",
            port:587,
            secure:false,
            auth:{
                user:USER,
                pass: PASS
            }
        });
        
        let info=await transporter.sendMail({
            from:USER,
            to:mail,
            subject:"Temporary password from EPIC CRM",
            text:"Please click the link below to reset your password",
            html:`<p>Your temporary password is  <b>${temp}</b></p>
                  <p>Copy the temporary password and submit it by clicking the 
                  temporary password link in the forgot password page</p>`
             })
        res.json({message:`mail sent to ${mail}`})
    }
        
     catch (error) {
      
      res.status(500).json({message:"Something went wrong,please try again"})
    }
}

let notificationMail=async(res,type,title,adminAndManagerMail)=>{
try {
    let today=new Date()
    let date=today.toDateString()
    let hr=today.getHours()
    let min=today.getMinutes()
    let sec=today.getSeconds()
    let time=`${hr}:${min}:${sec}`
    let transporter=nodemailer.createTransport({
        host:"smtp.gmail.com",
        port:587,
        secure:false,
        auth:{
            user:USER,
            pass: PASS
        }  
    });

    let info=await transporter.sendMail({
        from:USER,
        to:adminAndManagerMail,
        subject:`${type} created in EPIC CRM`,
        html:`<p>One <b>${type}</b> created with a title <b>${title}</b> on ${date} at ${time}</p>`
         });
    res.json({message:`${type} created and notification mail sent to top level authorities`}) 
    
} catch (error) {
  
    res.status(500).json({message:"Something went wrong"})
}
}

let adminAuth=(req,res,next)=>{
        try{
            if(req.headers.authorization){
      
                let decode=jwt.verify(req.headers.authorization,SECRET)

                if(decode.role ==="Admin" || decode.role === "Manager"){
                        next()
                 }else{
                        res.status(401).json({message:"Unauthorised"}) 
                    }
            }else{
              res.status(401).json({message:"Unauthorised"})
            }

        }catch(err){
            res.status(440).json({message:"Session expired,please login again"})
        }
   }


 let EmpAuth =(req,res,next)=>{
    try{
        if(req.headers.authorization){
            let decode=jwt.verify(req.headers.authorization,SECRET)
            
                if(decode.role === "Admin" || decode.role === "Manager"){
                    next()
                }else if(decode.role === "Employee"){
                   if(decode.access === true){
                    next()
                   }
                }else{
                    res.status(401).json({message:"Unauthorised"})
                }
            
         }else{
            res.status(401).json({message:"Unauthorised"})
         }
    }catch(err){
        res.status(440).json({message:"Session expired,please login again"})
    }
        
}

 
 let Auth=(req,res,next)=>{ 
       try{
        if(req.headers.authorization){
            let decode=jwt.verify(req.headers.authorization,SECRET)
            if(decode){
                next()
            }
        }else{
            res.status(401).json({message:"Unauthorised"})
        }
       }catch(err){ 
        res.status(440).json({message:"Session expired,please login again"})
       }
    }
    
app.post("/forgot",async(req,res)=>{
   
    try {
        let connection=await mongoclient.connect(URL);

        let db=connection.db(DB);

        let user=await db.collection("users").findOne({email:req.body.email});
        
        if(user){
        let temp=random.generate(8)
        let mail=user.email 
        await db.collection("users").findOneAndUpdate({email:mail},{$set:{temporaryPassword:temp}})
        
        sendEmail(res,temp,mail)
        }else{
            
            res.json({message:"User's mail id not valid"})
        }
    } catch (error) {
        
        res.status(500).json({message:"Sorry try again after sometime"})
    }
})

app.post("/temporarypass",async(req,res)=>{
    let pass=req.body.password
    let mail=req.body.email
   
    try {
        let connection=await mongoclient.connect(URL);

        let db=connection.db(DB);

        let user=await db.collection("users").findOne({email:mail})
        
        if(user){
            if(pass===user.temporaryPassword){

                await db.collection("users").findOneAndUpdate({email:user.email},{$unset:{temporaryPassword:""}})
                
                res.json({message:"Please change your password immediately"})
            }else{

                res.status(406).json({message:"email or password not matched"})
            }
        }else{
            
            res.status(406).json({message:"email or password not matched"})
        }
} catch (error) {
        res.status(500).json({message:"Something went wrong,try again"})
    }
})

app.post("/resetpass",async(req,res)=>{
    try {
        let connection=await mongoclient.connect(URL);

        let db=connection.db(DB);
            
        let user=await db.collection("users").findOne({email:req.body.email});

        if(user){
            let salt=await bcrypt.genSalt(10);

            let hash=await bcrypt.hash(req.body.password,salt);
     
            await db.collection("users").findOneAndUpdate({email:user.email},{$set:{password:hash}})

            res.json({message:"Password updated successfully"})
        }else{
            res.status(406).json({message:"Email id not valid"})
        }
    } catch (error) {
        res.status(500).json({message:"Something went wrong,try again"})
    }

})


app.post("/login",async(req,res)=>{
    
    try {
        let connection=await mongoclient.connect(URL);
      
        let db=connection.db(DB);
      
        let user=await db.collection("users").findOne({email:req.body.email});
        
        if(user){
        let compare=await bcrypt.compare(req.body.password,user.password);
         
        if(compare){
           
         let token=jwt.sign({_id:user._id,role:user.role,access:user.access},SECRET,{expiresIn:"5m"})

        res.json({token}) 
         
        }else{
            res.status(401).json({message:"email or password incorrect"});
        }
        }else{
          res.status(401).json({message:"email or password incorrect"});
        }
       } catch (error) {
        
        res.status(500).json({message:"something went wrong,try again"})
       }
      })

      
    app.post("/createuser",adminAuth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);
    
            let db=connection.db(DB);
    
            let user=await db.collection("users").findOne({email:req.body.email});
    
            if(!user){
                let salt=await bcrypt.genSalt(10);
    
                let hash=await bcrypt.hash(req.body.password,salt);
    
                req.body.password=hash;
    
                await db.collection("users").insertOne(req.body)
    
                res.json({message:"Account created successfully"})
            }else{
                res.status(409).json({message:"Email id already exists"})
            }
        } catch (error) {
            res.status(500).json({message:"Something went wrong,try again"})
        }
    
    })
    

    app.get("/users",Auth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let users=await db.collection("users").find().toArray();

            if(users.length != 0){

                res.json(users)
               }else{
                res.status(404).json({message:"No documents available"})
               } 
        } catch (error) {
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.get("/user/:id",adminAuth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let user=await db.collection("users").findOne({_id:mongodb.ObjectId( req.params.id)})

           if(user){

            res.json(user)
           }else{
            res.status(404).json({message:"invalid user id"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.put("/edituser/:id",adminAuth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let user=await db.collection("users").findOneAndUpdate({_id:mongodb.ObjectId( req.params.id)},{$set:req.body})

           if(user.value !== null){

            res.json({message:"Updated successfully"})
           }else{
            res.json({message:"invalid user id"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.delete("/user/:id",adminAuth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let user=await db.collection("users").findOneAndDelete({_id:mongodb.ObjectId( req.params.id)})
   
           if(user.value != null){

            res.json({message:"User deleted successfully"})
           }else{
            res.status(404).json({message:"invalid user id"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })


    app.get("/lead",Auth,async(req,res)=>{
        try {
           
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let leads=await db.collection("leads").find().toArray()

           if(leads.length != 0){

            res.json(leads)
           }else{
            res.status(404).json({message:"No documents available"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })


    app.post("/createlead",EmpAuth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let lead=await db.collection("leads").insertOne(req.body)

           if(lead.acknowledged){

            let topMail=[]
            await db.collection("users").find({$or:[{role:"Admin"},{role:"Manager"}]}).forEach(doc => topMail.push(doc.email));
             
            let adminAndManagerMail=topMail.toString()
            let type="Lead"
            let title=req.body.name
            
            notificationMail(res,type,title,adminAndManagerMail)
           }
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.get("/lead/:id",Auth,async(req,res)=>{
        try {
            
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let lead=await db.collection("leads").findOne({_id:mongodb.ObjectId( req.params.id)})

           if(lead){

            res.json(lead)
           }else{
            res.status(404).json({message:"invalid lead id"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.put("/lead/:id",EmpAuth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let lead=await db.collection("leads").findOneAndUpdate({_id:mongodb.ObjectId( req.params.id)},{$set:req.body})

           if(lead.value != null){

            res.json({message:"Lead updated successfully"})
           }else{
            res.status(404).json({message:"invalid user id"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.delete("/lead/:id",adminAuth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let lead=await db.collection("leads").findOneAndDelete({_id:mongodb.ObjectId( req.params.id)})
   
           if(lead.value != null){

            res.json({message:"Lead deleted successfully"})
           }else{
            res.status(404).json({message:"Invalid lead id"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.post("/createservice",async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let service=await db.collection("service requests").insertOne(req.body)

           if(service.acknowledged){

            let topMail=[]
            await db.collection("users").find({$or:[{role:"Admin"},{role:"Manager"}]}).forEach(doc => topMail.push(doc.email)
            );
             
            let adminAndManagerMail=topMail.toString()
            let type="Service Request"
            let title=req.body.name
         
            notificationMail(res,type,title,adminAndManagerMail)
          }
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.get("/service",Auth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let services=await db.collection("service requests").find().toArray()
 
            if(services.length != 0){

            res.json(services)
           }else{
            res.status(404).json({message:"No documents available"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.get("/service/:id",Auth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let lead=await db.collection("service requests").findOne({_id:mongodb.ObjectId( req.params.id)})

           if(lead){

            res.json(lead)
           }else{
            res.status(404).json({message:"invalid user id"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.put("/service/:id",EmpAuth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let request=await db.collection("service requests").findOneAndUpdate({_id:mongodb.ObjectId( req.params.id)},{$set:req.body})

           if(request.value != null){

            res.json({message:"Service Request updated successfully"})
           }else{
            res.status(404).json({message:"Invalid service request id"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

    app.delete("/service/:id",adminAuth,async(req,res)=>{
        try {
            let connection=await mongoclient.connect(URL);

            let db=connection.db(DB);

            let service=await db.collection("service requests").findOneAndDelete({_id:mongodb.ObjectId( req.params.id)});
   
           if(service.value != null){

            res.json({message:"Service Request deleted successfully"})
           }else{
            res.status(404).json({message:"invalid service request id"})
           } 
        } catch (error) {
           
            res.status(500).json({message:"Something went wrong,try again"})
        }
    })

   
    app.listen(process.env.PORT || 3001)