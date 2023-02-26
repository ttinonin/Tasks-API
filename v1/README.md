# PHP Tasks REST API 

This is an API build with pure PHP, and the routes are defined by the APACHE file `.htaccess`, make sure your APACHE server have the reqwrite modules option set to on.

## Endpoints

 - GET `/tasks` retrieve all tasks created. But remember, there is a pagination limited by a certain value (20)
 - GET `/tasks/$id` should return an specific task by it Id.
 - PATCH `/tasks/$id` should update the specific task by it Id.
 - DELETE `/tasks/$id` should delete the specific task by it Id.
 - POST `/tasks` create a task, providing title [required], description, deadline [required] and a completed (Y or N).

## Authentication

 - POST `/users` create a new user, providing fullname, username and a password.
 
 After the user creation, you should make a request to:

 - POST `/sessions` providing username and a password, then it provides you a accesstoken that expires after some amount of time (20 minutes).

 With the refresh token in hands, add it to the request method header as Authorization. Add it to every request you want to make.
