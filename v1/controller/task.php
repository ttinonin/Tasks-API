<?php
    require_once('db.php');
    require_once('../model/Task.php');
    require_once('../model/Response.php');

    try {
        $writeDB = DB::connectWriteDB();
        $readDB = DB::connectReadDB();
    } catch (PDOException $e) {
        error_log("Connection error - ".$e, 0);
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("Database connection error");
        $response->send();
        exit;
    }

    // Auth block
    if(!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1) {
        $response = new Response();
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage("Access token error");
        $response->send();
        exit;
    }

    $accesstoken = $_SERVER['HTTP_AUTHORIZATION'];

    try {
        $query = $writeDB->prepare('SELECT userid, accesstokenexpiry, useractive, loginattempts FROM tblsessions, tblusers WHERE tblsessions.userid = tblusers.id AND accesstoken = :accesstoken');
        $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);
        $query->execute();

        $rowCount = $query->rowCount();

        if($rowCount === 0) {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage("Invalid access token");
            $response->send();
            exit;
        }

        $row = $query->fetch(PDO::FETCH_ASSOC);

        $returned_userid = $row['userid'];
        $returned_accesstokenexpiry = $row['accesstokenexpiry'];
        $returned_useractive = $row['useractive'];
        $returned_loginattempts = $row['loginattempts'];

        if($returned_useractive !== 'Y') {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage("User account not active");
            $response->send();
            exit;
        }

        if($returned_loginattempts >= 3) {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage("Acount current blocked");
            $response->send();
            exit;
        }

        if(strtotime($returned_accesstokenexpiry) < time()) {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage("Token expired");
            $response->send();
            exit;
        }
    } catch(PDOException $e) {
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("There was an issue while authenticating");
        $response->send();
        exit;
    }

    // Get the taskid var by the url
    if(array_key_exists("taskid", $_GET)) {
        $taskid = $_GET['taskid'];

        if($taskid == '' || !is_numeric($taskid)) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage("Tasks ID cannot be blank or must be numeric");
            $response->send();
            exit;
        }

        if($_SERVER['REQUEST_METHOD'] === 'GET') {
            try {
                $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbltasks WHERE id = :taskid AND userid = :userid'); 
                $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();

                $rowCount = $query->rowCount();

                if($rowCount === 0) {
                    $response = new Response();
                    $response->setHttpStatusCode(404);
                    $response->addMessage("Task not found");
                    $response->send();
                    exit;
                }

                while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);

                    $taskArray[] = $task->returnTasksArray();
                }

                $returnData = array();
                $returnData['rows_returned'] = $rowCount;
                $returnData['tasks'] = $taskArray;

                $response = new Response();
                $response->setHttpStatusCode(200);
                $response->setSuccess(true);
                $response->toCache(true);
                $response->setData($returnData);
                $response->send();
                exit;
            } catch(TaskException $e) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage($e->getMessage());
                $response->send();
                exit;
            } catch(PDOException $e) {
                error_log("Database query error - ".$e, 0);
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to get task");
                $response->send();
                exit;
            }
        } elseif($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            try {
                $query = $writeDB->prepare('DELETE FROM tbltasks WHERE id = :taskid AND userid = :userid');
                $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();

                $rowCount = $query->rowCount();

                if($rowCount === 0) {
                    $response = new Response();
                    $response->setHttpStatusCode(404);
                    $response->setSuccess(false);
                    $response->addMessage("Task not found");
                    $response->send();
                    exit;
                }

                $response = new Response();
                $response->setHttpStatusCode(200);
                $response->setSuccess(true);
                $response->addMessage("Task deleted");
                $response->send();
                exit;
            } catch(PDOException $e) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to delete task");
                $response->send();
                exit;
            }
        } elseif($_SERVER['REQUEST_METHOD'] === 'PATCH') {
            try {
                if($_SERVER['CONTENT_TYPE'] !== 'application/json') {
                    $response = new Response();
                    $response->setHttpStatusCode(400);
                    $response->setSuccess(false);
                    $response->addMessage("Content type header not set to JSON");
                    $response->send();
                    exit;
                }

                $rawPatch = file_get_contents('php://input');

                if(!$jsonData = json_decode($rawPatch)) {
                    $response = new Response();
                    $response->setHttpStatusCode(400);
                    $response->setSuccess(false);
                    $response->addMessage("Request body is not valid JSON");
                    $response->send();
                    exit;
                }

                $title_updated = false;
                $description_updated = false;
                $deadline_updated = false;
                $completed_updated = false;

                $queryFieds = "";

                if(isset($jsonData->title)) {
                    $title_updated = true;
                    $queryFieds .= "title = :title, ";
                }

                if(isset($jsonData->description)) {
                    $description_updated = true;
                    $queryFieds .= "description = :description, ";
                }

                if(isset($jsonData->deadline)) {
                    $deadline_updated = true;
                    $queryFieds .= "deadline = STR_TO_DATE(:deadline, '%d/%m/%Y %H:%i'), ";
                }

                if(isset($jsonData->completed)) {
                    $completed_updated = true;
                    $queryFieds .= "completed = :completed";
                }

                $queryFieds = rtrim($queryFieds, ", ");

                if(!$title_updated && !$description_updated && !$deadline_updated && !$completed_updated) {
                    $response = new Response();
                    $response->setHttpStatusCode(400);
                    $response->setSuccess(false);
                    $response->addMessage("Fill out text fields");
                    $response->send();
                    exit;
                }

                $query = $writeDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbltasks WHERE id = :taskid AND userid = :userid');
                $query->bindParam(":taskid", $taskid, PDO::PARAM_INT);
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();

                $rowCount = $query->rowCount();

                if($rowCount === 0){
                    $response = new Response();
                    $response->setHttpStatusCode(404);
                    $response->setSuccess(false);
                    $response->addMessage("No task found to update");
                    $response->send();
                    exit;
                }

                while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    $task = new Task(
                        $row['id'],
                        $row['title'],
                        $row['description'],
                        $row['deadline'],
                        $row['completed']
                    );
                }

                $queryString = "UPDATE tbltasks SET ".$queryFieds." WHERE id = :taskid AND userid = :userid";
                $query = $writeDB->prepare($queryString);

                if($title_updated) {
                    $task->setTitle($jsonData->title);
                    $up_title = $task->getTitle();
                    $query->bindParam(':title', $up_title, PDO::PARAM_STR); 
                }
                
                if($description_updated) {
                    $task->setDescription($jsonData->description);
                    $up_description = $task->getDescription();
                    $query->bindParam(':description', $up_description, PDO::PARAM_STR); 
                }

                
                if($deadline_updated) {
                    $task->setDeadLine($jsonData->deadline);
                    $up_deadline = $task->getDeadline();
                    $query->bindParam(':deadline', $up_deadline, PDO::PARAM_STR); 
                }
                
                if($completed_updated) {
                    $task->setCompleted($jsonData->completed);
                    $up_completed = $task->getCompleted();
                    $query->bindParam(':completed', $up_completed, PDO::PARAM_STR); 
                }

                $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();

                $response = new Response();
                $response->setHttpStatusCode(200);
                $response->setSuccess(true);
                $response->addMessage("Task updated");
                $response->send();
                exit;
            } catch (TaskException $e) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage($e->getMessage());
                $response->send();
                exit;
            } catch (PDOException $e) {
                error_log("Database query error - ".$e, 0);
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to update task");
                $response->send();
                exit;
            }
        } else {
            $response = new Response();
            $response->setHttpStatusCode(405);
            $response->setSuccess(false);
            $response->addMessage("Request method not allowed");
            $response->send();
            exit;
        }
    }
    // Get the completed var by the url
    elseif(array_key_exists("completed", $_GET)) {
        $completed = $_GET['completed'];

        if($completed !== 'Y' && $completed !== 'N') {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage("Completed filter must be Y or N");
            $response->send();
            exit;
        }

        if($_SERVER['REQUEST_METHOD'] == 'GET') {
            try {
                $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbltasks WHERE completed = :completed AND userid = :userid');
                $query->bindParam(':completed', $completed, PDO::PARAM_STR);
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();

                $rowCount = $query->rowCount();

                $taskArray = array();

                while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);

                    $taskArray[] = $task->returnTasksArray();
                }

                $returnData = array();
                $returnData['rows_returned'] = $rowCount;
                $returnData['tasks'] = $taskArray;

                $response = new Response();
                $response->setHttpStatusCode(200);
                $response->setSuccess(true);
                $response->toCache(true);
                $response->setData($returnData);
                $response->send();
                exit;
            } catch(TaskException $e) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage($e->getMessage());
                $response->send();
                exit;
            } catch(PDOException $e) {
                error_log("Database query error - ".$e, 0);
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to get tasks");
                $response->send();
                exit;
            }
        } else {
            $response = new Response();
            $response->setHttpStatusCode(405);
            $response->setSuccess(false);
            $response->addMessage("Request method not allowed");
            $response->send();
            exit;
        }
    }
    elseif(array_key_exists("page", $_GET)) {
        if($_SERVER['REQUEST_METHOD'] == 'GET') {
            $page = $_GET['page'];

            if($page == '' || !is_numeric($page)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Page number cannot be blank and must be numeric");
                $response->send();
                exit;
            }

            $limitPerPage = 20;

            try {
                $query = $readDB->prepare('SELECT COUNT(id) as totalNoOfTasks FROM tbltasks WHERE userid = :userid');
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();

                $row = $query->fetch(PDO::FETCH_ASSOC);

                $tasksCount = intval($row['totalNoOfTasks']);

                $numOfPages = ceil($tasksCount/$limitPerPage);

                if($numOfPages == 0) {
                    $numOfPages = 1;
                }

                if($page > $numOfPages || $page == 0) {
                    $response = new Response();
                    $response->setHttpStatusCode(404);
                    $response->setSuccess(false);
                    $response->addMessage("Page not found");
                    $response->send();
                    exit;
                }

                $offset = ($page == 1 ? 0 : ($limitPerPage+($page-1)));

                $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbltasks WHERE userid = :userid LIMIT :pglimit OFFSET :offset');
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->bindParam(':pglimit', $limitPerPage, PDO::PARAM_INT);
                $query->bindParam(':offset', $offset, PDO::PARAM_INT);
                $query->execute();

                $rowCount = $query->rowCount();

                $taskArray = array();

                while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                    $taskArray[] = $task->returnTasksArray();
                }

                $returnData = array();
                $returnData['rows_returned'] = $rowCount;
                $returnData['total_rows'] = $tasksCount;
                $returnData['total_pages'] = $numOfPages;
                ($page < $numOfPages ? $returnData['has_next_page'] = true : $returnData['has_next_page'] = false);
                ($page > 1 ? $returnData['has_previous_page'] = true : $returnData['has_previous_page'] = false);
                $returnData['tasks'] = $taskArray;

                $response = new Response();
                $response->setHttpStatusCode(200);
                $response->setSuccess(true);
                $response->toCache(true);
                $response->setData($returnData);
                $response->send();
                exit;
            } catch (TaskException $e) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage($e->getMessage());
                $response->send();
                exit;
            } catch (PDOException $e) {
                error_log("Database query error - ".$e, 0);
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Failed to get tasks".$e);
                $response->send();
                exit;
            }
        } else {
            $response = new Response();
            $response->setHttpStatusCode(405);
            $response->setSuccess(false);
            $response->addMessage("Request method not allowed");
            $response->send();
            exit;
        }
    }
    elseif(empty($_GET)) {
        if($_SERVER['REQUEST_METHOD'] === 'GET') {
            try {
                $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbltasks WHERE userid = :userid');
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();

                $rowCount = $query->rowCount();

                $tasksArray = array();

                while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                    $taskArray[] = $task->returnTasksArray();
                }

                $returnData = array();
                $returnData['rows_returned'] = $rowCount;
                $returnData['tasks'] = $taskArray;

                $response = new Response();
                $response->setHttpStatusCode(200);
                $response->setSuccess(true);
                $response->toCache(true);
                $response->setData($returnData);
                $response->send();
                exit;
            } catch (TaskException $e) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage($e->getMessage());
                $response->send();
                exit;
            } catch (PDOException $e) {
                error_log("Database query error - ".$e, 0);
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to get tasks");
                $response->send();
                exit;
            }
        } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
            try {
                if($_SERVER['CONTENT_TYPE'] !== 'application/json') {
                    $response = new Response();
                    $response->setHttpStatusCode(400);
                    $response->setSuccess(false);
                    $response->addMessage('Content header is not set to JSON');
                    $response->send();
                    exit;
                }

                $rawPOSTData = file_get_contents('php://input');

                if(!$jsonData = json_decode($rawPOSTData)) {
                    $response = new Response();
                    $response->setHttpStatusCode(400);
                    $response->setSuccess(false);
                    $response->addMessage('Request body is not valid JSON');
                    $response->send();
                    exit;
                }

                if(!isset($jsonData->title) || !isset($jsonData->completed)) {
                    $response = new Response();
                    $response->setHttpStatusCode(400);
                    $response->setSuccess(false);
                    $response->addMessage("Please fill out the fields");
                    $response->send();
                    exit;
                }

                $newTask = new Task(
                    null, 
                    $jsonData->title, 
                    (isset($jsonData->description) ? $jsonData->description : null), 
                    (isset($jsonData->deadline) ? $jsonData->deadline : null),
                    $jsonData->completed
                );

                $title = $newTask->getTitle();
                $description = $newTask->getDescription();
                $deadline = $newTask->getDeadline();
                $completed = $newTask->getCompleted();

                $query = $writeDB->prepare('INSERT INTO tbltasks (title, description, deadline, completed, userid) VALUES (:title, :description, STR_TO_DATE(:deadline, \'%d/%m/%Y %H:%i\'), :completed, :userid)');
                $query->bindParam(':title', $title, PDO::PARAM_STR);
                $query->bindParam(':description', $description, PDO::PARAM_STR);
                $query->bindParam(':deadline', $deadline, PDO::PARAM_STR);
                $query->bindParam(':completed', $completed, PDO::PARAM_STR);
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();

                $rowCount = $query->rowCount();

                if($rowCount === 0) {
                    $response = new Response();
                    $response->setHttpStatusCode(500);
                    $response->setSuccess(false);
                    $response->addMessage("Failed to create task");
                    $response->send();
                    exit;
                }

                $response = new Response();
                $response->setHttpStatusCode(201);
                $response->setSuccess(true);
                $response->addMessage("Data created");
                $response->send();
                exit;
            } catch (TaskException $e) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage($e->getMessage());
                $response->send();
                exit;
            } catch (PDOException $e) {
                error_log("Database query error - ".$e, 0);
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to insert task into database");
                $response->send();
                exit;
            }
        } else {
            $response = new Response();
            $response->setHttpStatusCode(405);
            $response->setSuccess(false);
            $response->addMessage("Request method not allowed");
            $response->send();
            exit;
        }
    } else {
        $response = new Response();
        $response->setHttpStatusCode(404);
        $response->setSuccess(false);
        $response->addMessage("Endpoint not found");
        $response->send();
        exit;
    }
?>