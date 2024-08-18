import { asyncHandler } from "../utils/asynchandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudnary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import  jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        // Database me save karwaya hai
        user.refreshToken = refreshToken
        // validateBeforeSave isliye because :- while saving mongoDB will always check for password i.e. it is false  
       await user.save({validateBeforeSave: false})

       return {accessToken,refreshToken}

    } catch (error) {
        throw new ApiError(500,"Something went wrong while generating access and refresh token")
    }
}




const registerUser = asyncHandler(async (req,res)=>{
  //get user details from frontend
    // validation - not empty
    // check if user already exists : username, email
    // check for images check for avatar
    // upload them to cloudinary 
    // create user object- create entry in db
    // remove password and refresh token fields from response
    // check for user creation
    // return res


    //get user details from frontend
    const {fullName,email,username,password} = req.body
    // console.log(req.body);
    // console.log("Email is : ",email);
    // console.log("Password is : ",password);

    // validation - not empty
    if(
        [fullName,email,username,password].some((field)=>field?.trim()==="")
    ){
        throw new ApiError(400,"All fields are required");
    }

     // check if user already exists : username, email
    const existedUser = await User.findOne(
        {
            $or: [{username},{email}]
        }
    )
    if(existedUser){
        throw new ApiError(409,"User with email or username already exist")
    }

    // check for images check for avatar
    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is required");
    }


        // upload them to cloudinary 
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    if(!avatar){
        throw new ApiError(400,"Avatar file is required");
    }


     // create user object- create entry in db
    const user =  await User.create({
        fullName,
        avatar:avatar.url,
        coverImage:coverImage?.url || "",
        email,
        password,
        username:username.toLowerCase()
    })

        // remove password and refresh token fields from response
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

        // check for user creation
    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering the user")
    }

    // return res
    return res.status(201).json(
        new ApiResponse(200,createdUser,"User regisered successfully")
    )

})

const loginUser = asyncHandler(async(req,res)=>{
    // req.body ->data
    // username or email based login
    // find the user
    // access and refresh token
    // send cookie

        // req.body ->data
         // username or email based login
     const {username,email,password} = req.body
     if(!(username || email)){
        throw new ApiError(400,"Username or email required")
     }
      // find the user
     const user = await User.findOne({
        $or: [{username},{email}]
     })
     
     if(!user){
        throw new ApiError(404,"User does not exist")
     }

    const isPasswordValid =  await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401,"Password is incorrect")
     }

         // access and refresh token
     const {accessToken,refreshToken} = await generateAccessAndRefreshToken(user._id)

     const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

     const options = {
        httpOnly:true,
        secure:true
     }

     return res
     .status(200)
     .cookie("accessToken",accessToken)
     .cookie("refreshToken",refreshToken)
     .json(
        new ApiResponse(
            200,
            {
                user:loggedInUser,accessToken, refreshToken
            },
            "User loggedIn successfully"
        )
     )

})


const logoutUser = asyncHandler(async(req,res) => {
        await User.findByIdAndUpdate(
            req.user._id,
            {
                $set:{
                    refreshToken: undefined
                }
            },
            {
                new: true
            }
            
        )

        const options = {
            httpOnly:true,
            secure:true
         }

         return res
         .status(200)
         .clearCookie("accessToken",options)
         .clearCookie("refreshToken",options)
         .json(
            new ApiResponse(200,{},"User Logged Out")
         )
})


const refreshAccessToken = asyncHandler(async(req,res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401,"Unauthorized Request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401,"Invalid Refresh Token")
        }
    
        if(incomingRefreshToken != user?.refreshToken){
            throw new ApiError(401,"Refresh Token is Expired or used")
        }
    
        const options= {
            httpOnly : true,
            secure : true
        }
    
        const {accessToken,newrefreshToken} = await generateAccessAndRefreshToken(user._id)
    
        return res
             .status(200)
             .cookie("accessToken",accessToken,options)
             .cookie("refreshToken",newrefreshToken,options)
             .json(
                new ApiResponse(
                    200,
                    {accessToken, refreshToken:newrefreshToken},
                    "Access token refreshed successfully"
                )
    
             )
    } catch (error) {
        throw new ApiError(401,"Invaliddddd")
    }

})


const changeCurrentPassword = asyncHandler(async(req,res) => {
    const {oldPassword,newPassword} = req.body

    const user = await User.findById(req.user?._idid)

    const ispasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!ispasswordCorrect){
        throw new ApiError(400,"Invalid oldpassword")
    }
    user.password = newPassword
    await user.save({validateBeforeSave:false})

    return res
    .status(200)
    .json(new ApiResponse(200,{},"Password Changed Successfully"))


})


const getCurrentUser = asyncHandler(async(req,res) => {
    return res
    .status(200)
    .json(200,req.user,"Current User Fetched successfully")
})


const updateAccountDetails = asyncHandler(async(req,res) => {
    const {fullName,email} = req.body
    if(!fullName || !email){
        throw new ApiError(400,"All fields are required")
    }

    User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                // we can write in either way
                fullName,
                email:email
            }
        },
        {new:true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,user,"Accounts details updated successfully"))
})


const updateUserAvatar = asyncHandler(async(req,res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is missing")
    }
        const avatar =  await uploadOnCloudinary(avatarLocalPath)

        if(!avatar.url){
            throw new ApiError(400,"Error while uploading on avatar")
        }

        const user = await User.findByIdAndUpdate(
            req.user?._id,
            {
                $set:{
                    avatar:avatar.url
                }
            },
            {new: true}
        ).select("-password")

        return res
        .status(200)
        .json(new ApiResponse(200,user,"Avatar file Updated Successfully"))
})

const updateUserCoverImage = asyncHandler(async(req,res) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400,"Cover Image is missing")
    }
        const coverImage =  await uploadOnCloudinary(coverImageLocalPath)

        if(!coverImage.url){
            throw new ApiError(400,"Error while uploading the Cover Image")
        }

       const user =  await User.findByIdAndUpdate(
            req.user?._id,
            {
                $set:{
                    coverImage:coverImage.url
                }
            },
            {new: true}
        ).select("-password")

        return res
        .status(200)
        .json(new ApiResponse(200,user,"CoverImage Updated Successfully"))
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
}