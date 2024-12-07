package application;

// Import necessary JavaFX and utility classes
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class UserInterface extends Application {

    private Stage window; // Primary stage for the application
    private Login loginInstance = Login.getInstance(); // Singleton instance of Login class
    private User currentUser; // Currently logged-in user
    private String currentGroup = "all"; // Current active group
    private String currentLevel = "All"; // Current content level

    @Override
    public void start(Stage primaryStage) {
        window = primaryStage;
        window.setTitle("CSE 360 Help System");

        // Display the login screen when the application starts
        showLoginScreen();
    }

    // Method to display the login screen
    private void showLoginScreen() {
        VBox vbox = new VBox(10); // Vertical box layout with spacing of 10 pixels
        vbox.setPadding(new Insets(20));

        // Username input field
        TextField usernameField = new TextField();
        usernameField.setPromptText("Username");

        // Password input field
        PasswordField passwordField = new PasswordField();
        passwordField.setPromptText("Password");

        // Login button
        Button loginButton = new Button("Login");

        // Event handler for the login button
        loginButton.setOnAction(e -> {
            String username = usernameField.getText();
            String password = passwordField.getText();

            // If no users exist, register the first user as an Admin
            if (loginInstance.listUsers().isEmpty()) {
                User newUser = loginInstance.registerUser(username, password, "Admin", false, null);
                currentUser = newUser; // Set the current user
                showRegistrationScreen(newUser);
            } else {
                // Authenticate the user
                boolean isAuthenticated = loginInstance.authenticate(username, password);
                if (isAuthenticated) {
                    User user = loginInstance.findUser(username);
                    currentUser = user; // Set the current user
                    if (user != null && !user.isAccountSetupComplete()) {
                        // If account setup is incomplete, show the registration screen
                        showRegistrationScreen(user);
                    } else {
                        // Show role selection screen
                        showRoleSelectionScreen(user);
                    }
                } else {
                    System.out.println("Login failed. If this is a one-time password, it may have expired.");
                }
            }
        });

        // Add components to the layout
        vbox.getChildren().addAll(usernameField, passwordField, loginButton);

        // Set the scene and display the login screen
        Scene loginScene = new Scene(vbox, 400, 300);
        window.setScene(loginScene);
        window.show();
    }

    // Method to display the registration screen for account setup
    private void showRegistrationScreen(User user) {
        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));

        // Input fields for user details
        TextField emailField = new TextField();
        emailField.setPromptText("Email");

        TextField firstNameField = new TextField();
        firstNameField.setPromptText("First Name");

        TextField middleNameField = new TextField();
        middleNameField.setPromptText("Middle Name");

        TextField lastNameField = new TextField();
        lastNameField.setPromptText("Last Name");

        TextField preferredNameField = new TextField();
        preferredNameField.setPromptText("Preferred Name");

        // Map to store proficiency levels for topics
        Map<String, ComboBox<String>> topicComboBoxes = new HashMap<>();
        for (String topic : user.getTopics().keySet()) {
            // ComboBox for selecting proficiency level
            ComboBox<String> topicLevelBox = new ComboBox<>();
            topicLevelBox.getItems().addAll("Beginner", "Intermediate", "Advanced", "Expert");
            topicLevelBox.setValue(user.getTopicProficiency(topic)); // Set current proficiency level
            topicComboBoxes.put(topic, topicLevelBox);

            // Label and ComboBox for each topic
            Label topicLabel = new Label(topic);
            vbox.getChildren().addAll(topicLabel, topicLevelBox);
        }

        // Button to complete account setup
        Button registerButton = new Button("Complete Setup");

        // Event handler for the register button
        registerButton.setOnAction(e -> {
            // Set user details
            user.setEmail(emailField.getText());
            user.setFirstName(firstNameField.getText());
            user.setMiddleName(middleNameField.getText());
            user.setLastName(lastNameField.getText());
            user.setPreferredName(preferredNameField.getText());

            // Set proficiency levels for topics
            for (String topic : topicComboBoxes.keySet()) {
                user.setTopicProficiency(topic, topicComboBoxes.get(topic).getValue());
            }

            user.setAccountSetupComplete(true); // Mark account setup as complete
            System.out.println("Account setup completed.");
            showRoleSelectionScreen(user); // Proceed to role selection screen
        });

        // Add components to the layout
        vbox.getChildren().addAll(emailField, firstNameField, middleNameField, lastNameField, preferredNameField, registerButton);

        // Set the scene and display the registration screen
        Scene registerScene = new Scene(vbox, 400, 600);
        window.setScene(registerScene);
        window.show();
    }

    // Method to display the role selection screen
    private void showRoleSelectionScreen(User user) {
        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));

        // ComboBox to select the user's role
        ComboBox<String> roleDropdown = new ComboBox<>();
        roleDropdown.getItems().addAll(user.getRole()); // User's available roles
        roleDropdown.setPromptText("Select Role");

        // Button to confirm role selection
        Button selectButton = new Button("Select Role");

        // Event handler for the select button
        selectButton.setOnAction(e -> {
            String selectedRole = roleDropdown.getValue();
            System.out.println("Role Selected: " + selectedRole);
            if ("Admin".equalsIgnoreCase(selectedRole)) {
                showAdminDashboard(user); // Show admin dashboard
            } else if ("Instructor".equalsIgnoreCase(selectedRole)) {
                showInstructorDashboard(user); // Show instructor dashboard
            } else {
                showSimpleHomePage(user); // Show student home page
            }
        });

        // Add components to the layout
        vbox.getChildren().addAll(new Label("Select Role"), roleDropdown, selectButton);

        // Set the scene and display the role selection screen
        Scene roleScene = new Scene(vbox, 400, 200);
        window.setScene(roleScene);
        window.show();
    }

    // Method to display the student's home page
    private void showSimpleHomePage(User user) {
        currentUser = user; // Set the current user

        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));
        Button logoutButton = new Button("Logout");

        // Search functionality components
        TextField searchField = new TextField();
        searchField.setPromptText("Enter keyword to search");

        // ComboBox for content level
        ComboBox<String> levelComboBox = new ComboBox<>();
        levelComboBox.getItems().addAll("All", "Beginner", "Intermediate", "Advanced", "Expert");
        levelComboBox.setValue("All");
        levelComboBox.setPromptText("Select Content Level");

        // ComboBox for group selection
        ComboBox<String> groupComboBox = new ComboBox<>();
        List<String> groupOptions = new ArrayList<>(currentUser.getGroupNames());
        groupOptions.add(0, "all");
        groupComboBox.getItems().addAll(groupOptions);
        groupComboBox.setValue("all");
        groupComboBox.setPromptText("Select Group");

        Button searchButton = new Button("Search Articles");

        // Labels to display active group and number of articles matching each level
        Label activeGroupLabel = new Label("Active Group: all");
        Label articleCountLabel = new Label("Articles Matching Levels:");

        ListView<String> articlesListView = new ListView<>(); // ListView to display article titles

        // Map to associate sequence numbers with articles
        Map<Integer, User.HelpArticle> sequenceToArticleMap = new HashMap<>();

        // Event handler for the search button
        searchButton.setOnAction(e -> {
            String keyword = searchField.getText().trim().toLowerCase();
            String selectedLevel = levelComboBox.getValue();
            String selectedGroup = groupComboBox.getValue();

            currentLevel = selectedLevel;
            currentGroup = selectedGroup;

            activeGroupLabel.setText("Active Group: " + currentGroup);

            // ** Log the search query **
            loginInstance.addSearchQuery(currentUser.getUsername(), keyword);

            // Collect all help articles from all users
            List<User.HelpArticle> results = new ArrayList<>();
            for (User u : loginInstance.listUsers()) {
                results.addAll(u.getAllHelpArticles());
            }

            // Filter articles that the user has access to
            results.removeIf(article -> !article.userHasAccess(currentUser));

            // Filter articles based on keyword
            if (keyword != null && !keyword.isEmpty()) {
                results.removeIf(article -> !articleMatchesKeyword(article, keyword));
            }

            // Filter articles by group and level
            List<User.HelpArticle> filteredArticles = new ArrayList<>();
            for (User.HelpArticle article : results) {
                boolean groupMatch = currentGroup.equals("all") || article.getGroups().contains(currentGroup);
                boolean levelMatch = currentLevel.equals("All") || article.getLevel().equalsIgnoreCase(currentLevel);
                if (groupMatch && levelMatch) {
                    filteredArticles.add(article);
                }
            }

            // Count articles by level
            Map<String, Integer> levelCounts = new HashMap<>();
            for (String level : Arrays.asList("Beginner", "Intermediate", "Advanced", "Expert")) {
                levelCounts.put(level, 0);
            }
            for (User.HelpArticle article : filteredArticles) {
                String level = article.getLevel();
                levelCounts.put(level, levelCounts.getOrDefault(level, 0) + 1);
            }

            // Update article count label
            StringBuilder countText = new StringBuilder("Articles Matching Levels:\n");
            for (String level : Arrays.asList("Beginner", "Intermediate", "Advanced", "Expert")) {
                countText.append(level).append(": ").append(levelCounts.get(level)).append("\n");
            }
            articleCountLabel.setText(countText.toString());

            // Display articles in short form
            articlesListView.getItems().clear();
            sequenceToArticleMap.clear();
            int sequenceNumber = 1;
            for (User.HelpArticle article : filteredArticles) {
                String itemText = sequenceNumber + ". Title: " + article.getTitle() + ", Author: " + article.getAuthor() + ", Abstract: " + article.getDescription();
                articlesListView.getItems().add(itemText);
                sequenceToArticleMap.put(sequenceNumber, article);
                sequenceNumber++;
            }
        });

        // Event handler for selecting an article to view details using sequence number
        articlesListView.setOnMouseClicked(event -> {
            if (event.getClickCount() == 2) { // Double-click
                String selectedItem = articlesListView.getSelectionModel().getSelectedItem();
                if (selectedItem != null) {
                    // Extract sequence number from the selected item
                    int dotIndex = selectedItem.indexOf(".");
                    if (dotIndex != -1) {
                        String sequenceStr = selectedItem.substring(0, dotIndex);
                        try {
                            int sequenceNumber = Integer.parseInt(sequenceStr.trim());
                            User.HelpArticle article = sequenceToArticleMap.get(sequenceNumber);
                            if (article != null) {
                                showArticleDetail(article);
                            }
                        } catch (NumberFormatException ex) {
                            System.out.println("Invalid sequence number.");
                        }
                    }
                }
            }
        });

        // Message sending components
        TextArea genericMessageArea = new TextArea();
        genericMessageArea.setPromptText("Enter your generic message here...");
        genericMessageArea.setPrefRowCount(2);

        Button sendGenericMessageButton = new Button("Send Generic Message");
        sendGenericMessageButton.setOnAction(e -> {
            String messageContent = genericMessageArea.getText();
            if (messageContent != null && !messageContent.isEmpty()) {
                loginInstance.addMessage(currentUser.getUsername(), "Generic Message: " + messageContent);
                genericMessageArea.clear();
                System.out.println("Generic message sent.");
            } else {
                System.out.println("Please enter a message to send.");
            }
        });

        TextArea specificMessageArea = new TextArea();
        specificMessageArea.setPromptText("Enter your specific message here...");
        specificMessageArea.setPrefRowCount(2);

        Button sendSpecificMessageButton = new Button("Send Specific Message");
        sendSpecificMessageButton.setOnAction(e -> {
            String messageContent = specificMessageArea.getText();
            if (messageContent != null && !messageContent.isEmpty()) {
                loginInstance.addMessage(currentUser.getUsername(), "Specific Message: " + messageContent);
                specificMessageArea.clear();
                System.out.println("Specific message sent.");
            } else {
                System.out.println("Please enter a message to send.");
            }
        });

        // Event handler for the logout button
        logoutButton.setOnAction(e -> {
            System.out.println("Logging out.");
            showLoginScreen(); // Return to login screen
        });

        // Layout for search options
        HBox searchOptions = new HBox(10);
        searchOptions.getChildren().addAll(new Label("Content Level:"), levelComboBox, new Label("Group:"), groupComboBox);

        // Add components to the layout
        vbox.getChildren().addAll(
                new Label("Student Home Page"),
                new Separator(),
                searchField,
                searchOptions,
                searchButton,
                activeGroupLabel,
                articleCountLabel,
                new Label("Search Results:"),
                articlesListView,
                new Separator(),
                new Label("Send a Generic Message to Instructors/Admins:"),
                genericMessageArea, sendGenericMessageButton,
                new Separator(),
                new Label("Send a Specific Message (e.g., request for help articles):"),
                specificMessageArea, sendSpecificMessageButton,
                new Separator(),
                logoutButton);

        // Set the scene and display the home page
        Scene homeScene = new Scene(vbox, 600, 800);
        window.setScene(homeScene);
        window.show();
    }

    // Method to display the instructor dashboard
    private void showInstructorDashboard(User user) {
        currentUser = user; // Set the current user

        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));

        // Search functionality components (same as student)
        TextField searchField = new TextField();
        searchField.setPromptText("Enter keyword to search");

        // ComboBox for content level
        ComboBox<String> levelComboBox = new ComboBox<>();
        levelComboBox.getItems().addAll("All", "Beginner", "Intermediate", "Advanced", "Expert");
        levelComboBox.setValue("All");
        levelComboBox.setPromptText("Select Content Level");

        // ComboBox for group selection
        ComboBox<String> groupComboBox = new ComboBox<>();
        Set<String> allGroups = new HashSet<>();
        allGroups.add("all");
        for (Group group : loginInstance.listGroups()) {
            allGroups.add(group.getGroupName());
        }
        groupComboBox.getItems().addAll(allGroups);
        groupComboBox.setValue("all");
        groupComboBox.setPromptText("Select Group");

        Button searchButton = new Button("Search Articles");

        // Labels to display active group and number of articles matching each level
        Label activeGroupLabel = new Label("Active Group: all");
        Label articleCountLabel = new Label("Articles Matching Levels:");

        ListView<String> articlesListView = new ListView<>(); // ListView to display article titles
        articlesListView.setPrefHeight(200); // Set preferred height

        // Map to associate sequence numbers with articles
        Map<Integer, User.HelpArticle> sequenceToArticleMap = new HashMap<>();

        // Event handler for the search button
        searchButton.setOnAction(e -> {
            String keyword = searchField.getText().trim().toLowerCase();
            String selectedLevel = levelComboBox.getValue();
            String selectedGroup = groupComboBox.getValue();

            currentLevel = selectedLevel;
            currentGroup = selectedGroup;

            activeGroupLabel.setText("Active Group: " + currentGroup);

            // ** Log the search query **
            loginInstance.addSearchQuery(currentUser.getUsername(), keyword);

            List<User.HelpArticle> results = new ArrayList<>();

            // Collect all help articles from all users
            for (User u : loginInstance.listUsers()) {
                results.addAll(u.getAllHelpArticles());
            }

            // Filter articles based on keyword
            if (keyword != null && !keyword.isEmpty()) {
                results.removeIf(article -> !articleMatchesKeyword(article, keyword));
            }

            // Filter articles by group and level
            List<User.HelpArticle> filteredArticles = new ArrayList<>();
            for (User.HelpArticle article : results) {
                boolean groupMatch = currentGroup.equals("all") || article.getGroups().contains(currentGroup);
                boolean levelMatch = currentLevel.equals("All") || article.getLevel().equalsIgnoreCase(currentLevel);
                if (groupMatch && levelMatch) {
                    filteredArticles.add(article);
                }
            }

            // Count articles by level
            Map<String, Integer> levelCounts = new HashMap<>();
            for (String level : Arrays.asList("Beginner", "Intermediate", "Advanced", "Expert")) {
                levelCounts.put(level, 0);
            }
            for (User.HelpArticle article : filteredArticles) {
                String level = article.getLevel();
                levelCounts.put(level, levelCounts.getOrDefault(level, 0) + 1);
            }

            // Update article count label
            StringBuilder countText = new StringBuilder("Articles Matching Levels:\n");
            for (String level : Arrays.asList("Beginner", "Intermediate", "Advanced", "Expert")) {
                countText.append(level).append(": ").append(levelCounts.get(level)).append("\n");
            }
            articleCountLabel.setText(countText.toString());

            // Display articles in short form
            articlesListView.getItems().clear();
            sequenceToArticleMap.clear();
            int sequenceNumber = 1;
            for (User.HelpArticle article : filteredArticles) {
                String itemText = sequenceNumber + ". Title: " + article.getTitle() + ", Author: " + article.getAuthor() + ", Abstract: " + article.getDescription();
                articlesListView.getItems().add(itemText);
                sequenceToArticleMap.put(sequenceNumber, article);
                sequenceNumber++;
            }
        });

        // Event handler for selecting an article to view details using sequence number
        articlesListView.setOnMouseClicked(event -> {
            if (event.getClickCount() == 2) { // Double-click
                String selectedItem = articlesListView.getSelectionModel().getSelectedItem();
                if (selectedItem != null) {
                    // Extract sequence number from the selected item
                    int dotIndex = selectedItem.indexOf(".");
                    if (dotIndex != -1) {
                        String sequenceStr = selectedItem.substring(0, dotIndex);
                        try {
                            int sequenceNumber = Integer.parseInt(sequenceStr.trim());
                            User.HelpArticle article = sequenceToArticleMap.get(sequenceNumber);
                            if (article != null) {
                                showArticleDetail(article);
                            }
                        } catch (NumberFormatException ex) {
                            System.out.println("Invalid sequence number.");
                        }
                    }
                }
            }
        });

        // Input fields for article details (for adding/editing articles)
        TextField titleField = new TextField();
        titleField.setPromptText("Title");

        TextField descriptionField = new TextField();
        descriptionField.setPromptText("Description");

        TextField keywordsField = new TextField();
        keywordsField.setPromptText("Keywords (comma-separated)");

        TextArea bodyArea = new TextArea();
        bodyArea.setPromptText("Body of the article");

        TextField groupsField = new TextField();
        groupsField.setPromptText("Groups (comma-separated)");

        TextField levelField = new TextField();
        levelField.setPromptText("Level (Beginner, Intermediate, Advanced, Expert)");

        // Buttons for article management
        Button addArticleButton = new Button("Add Article");
        Button editArticleButton = new Button("Edit Selected Article");
        Button deleteArticleButton = new Button("Delete Selected Article");

        // Event handler for adding a new article
        addArticleButton.setOnAction(e -> {
            addArticle(
                    titleField.getText(), descriptionField.getText(),
                    Arrays.asList(keywordsField.getText().split(",")),
                    bodyArea.getText(), new ArrayList<>(),
                    Arrays.asList(groupsField.getText().split(",")), levelField.getText());
            clearArticleInputFields(titleField, descriptionField, keywordsField, bodyArea, groupsField, levelField);
        });

        // Event handler for editing an article
        editArticleButton.setOnAction(e -> {
            String selectedItem = articlesListView.getSelectionModel().getSelectedItem();
            if (selectedItem != null) {
                int dotIndex = selectedItem.indexOf(".");
                if (dotIndex != -1) {
                    String sequenceStr = selectedItem.substring(0, dotIndex);
                    try {
                        int sequenceNumber = Integer.parseInt(sequenceStr.trim());
                        User.HelpArticle article = sequenceToArticleMap.get(sequenceNumber);
                        if (article != null && article.getAuthor().equals(currentUser.getUsername())) {
                            // Update the article with new details
                            article.setTitle(titleField.getText());
                            article.setDescription(descriptionField.getText());
                            article.setKeywords(Arrays.asList(keywordsField.getText().split(",")));
                            article.setBody(bodyArea.getText());
                            article.setGroups(Arrays.asList(groupsField.getText().split(",")));
                            article.setLevel(levelField.getText());
                            System.out.println("Article updated.");
                            clearArticleInputFields(titleField, descriptionField, keywordsField, bodyArea, groupsField, levelField);
                        } else {
                            System.out.println("You can only edit your own articles.");
                        }
                    } catch (NumberFormatException ex) {
                        System.out.println("Invalid sequence number.");
                    }
                }
            } else {
                System.out.println("No article selected for editing.");
            }
        });

        // Event handler for deleting an article
        deleteArticleButton.setOnAction(e -> {
            String selectedItem = articlesListView.getSelectionModel().getSelectedItem();
            if (selectedItem != null) {
                int dotIndex = selectedItem.indexOf(".");
                if (dotIndex != -1) {
                    String sequenceStr = selectedItem.substring(0, dotIndex);
                    try {
                        int sequenceNumber = Integer.parseInt(sequenceStr.trim());
                        User.HelpArticle article = sequenceToArticleMap.get(sequenceNumber);
                        if (article != null && article.getAuthor().equals(currentUser.getUsername())) {
                            currentUser.removeHelpArticle(article.getId());
                            System.out.println("Article deleted.");
                            articlesListView.getItems().remove(selectedItem);
                        } else {
                            System.out.println("You can only delete your own articles.");
                        }
                    } catch (NumberFormatException ex) {
                        System.out.println("Invalid sequence number.");
                    }
                }
            } else {
                System.out.println("No article selected for deletion.");
            }
        });

        // Group management components
        TextField groupNameField = new TextField();
        groupNameField.setPromptText("Enter Group Name");

        CheckBox specialAccessCheckBox = new CheckBox("Special Access Group");

        Button createGroupButton = new Button("Create Group");
        Button addUserToGroupButton = new Button("Add User to Group");
        Button removeUserFromGroupButton = new Button("Remove User from Group");
        Button listGroupsButton = new Button("List Groups");
        
     // View groups
        Label GroupsLabel = new Label("Registered Groups:");
        TextArea GroupsArea = new TextArea();
        GroupsArea.setEditable(false);
        GroupsArea.setPrefRowCount(5);

        // Event handler for creating a group
        createGroupButton.setOnAction(e -> {
            String groupName = groupNameField.getText();
            boolean isSpecialAccess = specialAccessCheckBox.isSelected();
            if (!groupName.isEmpty()) {
                Group group = loginInstance.createGroup(groupName, isSpecialAccess);
                if (group != null) {
                    System.out.println("Group created successfully.");
                    groupComboBox.getItems().add(groupName); // Update group selection ComboBox
                } else {
                    System.out.println("Failed to create group.");
                }
            } else {
                System.out.println("Please enter a group name.");
            }
        });

        // Event handler for adding a user to a group
        addUserToGroupButton.setOnAction(e -> {
            String groupName = groupNameField.getText();
            TextInputDialog dialog = new TextInputDialog();
            dialog.setTitle("Add User to Group");
            dialog.setHeaderText("Enter the username to add to the group:");
            Optional<String> result = dialog.showAndWait();
            result.ifPresent(usernameToAdd -> {
                User userToAdd = loginInstance.findUser(usernameToAdd);
                if (userToAdd != null) {
                    boolean added = loginInstance.addUserToGroup(groupName, userToAdd);
                    if (added) {
                        System.out.println("User added to group successfully.");
                    } else {
                        System.out.println("Failed to add user to group.");
                    }
                } else {
                    System.out.println("User not found.");
                }
            });
        });

        // Event handler for removing a user from a group
        removeUserFromGroupButton.setOnAction(e -> {
            String groupName = groupNameField.getText();
            TextInputDialog dialog = new TextInputDialog();
            dialog.setTitle("Remove User from Group");
            dialog.setHeaderText("Enter the username to remove from the group:");
            Optional<String> result = dialog.showAndWait();
            result.ifPresent(usernameToRemove -> {
                User userToRemove = loginInstance.findUser(usernameToRemove);
                if (userToRemove != null) {
                    boolean removed = loginInstance.removeUserFromGroup(groupName, userToRemove);
                    if (removed) {
                        System.out.println("User removed from group successfully.");
                    } else {
                        System.out.println("Failed to remove user from group.");
                    }
                } else {
                    System.out.println("User not found.");
                }
            });
        });

     // Event handler for listing all groups
        listGroupsButton.setOnAction(e -> {
            StringBuilder groupsList = new StringBuilder("Listing all groups:\n");

            // Iterate through the list of groups and append each to the StringBuilder
            for (Group g : loginInstance.listGroups()) {
                groupsList.append("Group: ").append(g.getGroupName()).append(", Special Access: ").append(g.isSpecialAccess()).append("\n");
            }

            // Set the text of groupArea to show the list of groups
            GroupsArea.setText(groupsList.toString());
        });

        // Backup and Restore buttons
        Button backupButton = new Button("Backup Articles");
        Button restoreButton = new Button("Restore Articles");

        backupButton.setOnAction(e -> backupArticles());
        restoreButton.setOnAction(e -> restoreArticles());

        // Logout button
        Button logoutButton = new Button("Logout");
        logoutButton.setOnAction(e -> {
            System.out.println("Logging out.");
            showLoginScreen(); // Return to login screen
        });

        // Layouts for organizing components
        HBox searchOptions = new HBox(10);
        searchOptions.getChildren().addAll(new Label("Content Level:"), levelComboBox, new Label("Group:"), groupComboBox);

        HBox articleButtons = new HBox(10);
        articleButtons.getChildren().addAll(addArticleButton, editArticleButton, deleteArticleButton);

        HBox groupButtons = new HBox(10);
        groupButtons.getChildren().addAll(createGroupButton, addUserToGroupButton, removeUserFromGroupButton, listGroupsButton);

        // Add components to the layout
        vbox.getChildren().addAll(
                new Label("Instructor Dashboard"),
                new Separator(),
                searchField,
                searchOptions,
                searchButton,
                activeGroupLabel,
                articleCountLabel,
                new Label("Search Results:"),
                articlesListView, // Add the articlesListView to the layout
                new Separator(),
                new Label("Article Management:"),
                titleField, descriptionField, keywordsField, bodyArea, groupsField, levelField,
                articleButtons,
                new Separator(),
                new Label("Group Management:"),
                groupNameField, specialAccessCheckBox,
                groupButtons,
                GroupsLabel, GroupsArea,
                new Separator(),
                backupButton, restoreButton,
                new Separator(),
                logoutButton); // Ensure logoutButton is added
        
        // Wrap the VBox in a ScrollPane
        ScrollPane scrollPane = new ScrollPane(vbox);
        scrollPane.setFitToWidth(true); // Ensure the scroll pane fits the width of the content

        // Set the scene with the scroll pane
        Scene instructorScene = new Scene(scrollPane, 800, 600); // Adjusted window height to 600
        window.setScene(instructorScene);
        window.show();
    }

    
    // Helper method to check if an article matches the keyword
    private boolean articleMatchesKeyword(User.HelpArticle article, String keyword) {
        if (article.getTitle().toLowerCase().contains(keyword)) {
            return true;
        }
        if (article.getDescription().toLowerCase().contains(keyword)) {
            return true;
        }
        if (article.getBody(currentUser).toLowerCase().contains(keyword)) {
            return true;
        }
        // Check keywords
        for (String k : article.getKeywords()) {
            if (k.toLowerCase().contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    // Method to clear article input fields
    private void clearArticleInputFields(TextField titleField, TextField descriptionField, TextField keywordsField,
                                         TextArea bodyArea, TextField groupsField, TextField levelField) {
        titleField.clear();
        descriptionField.clear();
        keywordsField.clear();
        bodyArea.clear();
        groupsField.clear();
        levelField.clear();
    }

    // Method to show article details
    private void showArticleDetail(User.HelpArticle article) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Article Detail");
        alert.setHeaderText(article.getTitle());
        alert.setContentText("Author: " + article.getAuthor() + "\n\n" + article.getBody(currentUser));
        alert.showAndWait();
    }

    // Method to add a new article to the current user's list
    private void addArticle(String title, String description, List<String> keywords, String body, List<String> links, List<String> groups, String level) {
        if (currentUser != null) {
            User.HelpArticle newArticle = new User.HelpArticle(
                    System.currentTimeMillis(), // Unique ID
                    title, description, keywords, body, links, groups, level, currentUser.getUsername()
            );
            currentUser.addHelpArticle(newArticle); // Add the new article
            System.out.println("Article Added: " + title);
        } else {
            System.out.println("No user is currently logged in.");
        }
    }

    // Method to backup articles to a file
    private void backupArticles() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save Backup");
        File file = fileChooser.showSaveDialog(window); // Show save dialog
        if (file != null) {
            loginInstance.backupHelpArticles(file.getAbsolutePath(), currentUser); // Backup articles
            System.out.println("Backup completed.");
        }
    }

    // Method to restore articles from a file
    private void restoreArticles() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Backup File");
        File file = fileChooser.showOpenDialog(window); // Show open dialog
        if (file != null) {
            // Confirmation dialog for merge option
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION, "Do you want to merge with existing articles?", ButtonType.YES, ButtonType.NO);
            alert.showAndWait().ifPresent(response -> {
                boolean merge = response == ButtonType.YES;
                loginInstance.restoreHelpArticles(file.getAbsolutePath(), merge, currentUser); // Restore articles
                System.out.println("Restore completed.");
            });
        }
    }
    
    // Adjusted method for deleting a group in Login class (Assuming we can add it)
    private boolean deleteGroupByName(String groupName) {
        return loginInstance.deleteGroup(groupName);
    }
    
    

    // Method to display the admin dashboard
    private void showAdminDashboard(User user) {
        currentUser = user; // Set the current user

        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));

        // User Management Components
        Label userManagementLabel = new Label("User Management:");
        TextField usernameField = new TextField();
        usernameField.setPromptText("Username");

        PasswordField passwordField = new PasswordField();
        passwordField.setPromptText("Password");

        ComboBox<String> roleComboBox = new ComboBox<>();
        roleComboBox.getItems().addAll("Student", "Instructor", "Admin");
        roleComboBox.setValue("Student");

        Button addUserButton = new Button("Add User");
        Button deleteUserButton = new Button("Delete User");
        Button listUsersButton = new Button("List Users");
        
     // View Registered Users
        Label UserLabel = new Label("Registered Users:");
        TextArea UserArea = new TextArea();
        UserArea.setEditable(false);
        UserArea.setPrefRowCount(5);

        // Event handler for adding a user
        addUserButton.setOnAction(e -> {
            String username = usernameField.getText();
            String password = passwordField.getText();
            String role = roleComboBox.getValue();
            boolean isOneTimePassword = false;

            // Register the new user
            if (!username.isEmpty() && !password.isEmpty()) {
                User newUser = loginInstance.registerUser(username, password, role, isOneTimePassword, null);
                if (newUser != null) {
                    System.out.println("User added successfully.");
                } else {
                    System.out.println("Failed to add user.");
                }
            } else {
                System.out.println("Please enter a username and password.");
            }
        });

        // Event handler for deleting a user
        deleteUserButton.setOnAction(e -> {
            String usernameToDelete = usernameField.getText();
            if (!usernameToDelete.isEmpty()) {
                boolean isDeleted = loginInstance.deleteUser(usernameToDelete);
                if (isDeleted) {
                    System.out.println("User deleted successfully.");
                } else {
                    System.out.println("Failed to delete user.");
                }
            } else {
                System.out.println("Please enter a username.");
            }
        });

     // Event handler for listing all users
        listUsersButton.setOnAction(e -> {
            StringBuilder usersList = new StringBuilder("Listing all users:\n");

            // Iterate through the list of users and append each to the StringBuilder
            for (User u : loginInstance.listUsers()) {
                usersList.append("Username: ").append(u.getUsername()).append(", Role: ").append(u.getRole()).append("\n");
            }

            // Set the text of UserArea to show the list of users
            UserArea.setText(usersList.toString());
        });

        // Group Management Components
        Label groupManagementLabel = new Label("Group Management:");
        TextField groupNameField = new TextField();
        groupNameField.setPromptText("Group Name");

        CheckBox specialAccessCheckBox = new CheckBox("Special Access Group");

        Button createGroupButton = new Button("Create Group");
        Button deleteGroupButton = new Button("Delete Group");
        Button listGroupsButton = new Button("List Groups");
        
     // View Messages and Search History
        Label GroupsLabel = new Label("Registered Groups:");
        TextArea GroupsArea = new TextArea();
        GroupsArea.setEditable(false);
        GroupsArea.setPrefRowCount(5);

        // Event handler for creating a group
        createGroupButton.setOnAction(e -> {
            String groupName = groupNameField.getText();
            boolean isSpecialAccess = specialAccessCheckBox.isSelected();
            if (!groupName.isEmpty()) {
                Group group = loginInstance.createGroup(groupName, isSpecialAccess);
                if (group != null) {
                    System.out.println("Group created successfully.");
                } else {
                    System.out.println("Failed to create group.");
                }
            } else {
                System.out.println("Please enter a group name.");
            }
        });

        // Event handler for deleting a group
        deleteGroupButton.setOnAction(e -> {
            String groupName = groupNameField.getText();
            if (!groupName.isEmpty()) {
                boolean isDeleted = loginInstance.deleteGroup(groupName);
                if (isDeleted) {
                    System.out.println("Group deleted successfully.");
                } else {
                    System.out.println("Failed to delete group.");
                }
            } else {
                System.out.println("Please enter a group name.");
            }
        });

     // Event handler for listing all groups
        listGroupsButton.setOnAction(e -> {
            StringBuilder groupsList = new StringBuilder("Listing all groups:\n");

            // Iterate through the list of groups and append each to the StringBuilder
            for (Group g : loginInstance.listGroups()) {
                groupsList.append("Group: ").append(g.getGroupName()).append(", Special Access: ").append(g.isSpecialAccess()).append("\n");
            }

            // Set the text of groupArea to show the list of groups
            GroupsArea.setText(groupsList.toString());
        });

        // Group Membership Management
        Label groupMembershipLabel = new Label("Group Membership Management:");
        Button addUserToGroupButton = new Button("Add User to Group");
        Button removeUserFromGroupButton = new Button("Remove User from Group");
        Button listGroupMembersButton = new Button("List Group Members");

        // Event handler for adding a user to a group
        addUserToGroupButton.setOnAction(e -> {
            String groupName = groupNameField.getText();
            String usernameToAdd = usernameField.getText();
            if (!groupName.isEmpty() && !usernameToAdd.isEmpty()) {
                User userToAdd = loginInstance.findUser(usernameToAdd);
                if (userToAdd != null) {
                    boolean added = loginInstance.addUserToGroup(groupName, userToAdd);
                    if (added) {
                        System.out.println("User added to group successfully.");
                    } else {
                        System.out.println("Failed to add user to group.");
                    }
                } else {
                    System.out.println("User not found.");
                }
            } else {
                System.out.println("Please enter both group name and username.");
            }
        });

        // Event handler for removing a user from a group
        removeUserFromGroupButton.setOnAction(e -> {
            String groupName = groupNameField.getText();
            String usernameToRemove = usernameField.getText();
            if (!groupName.isEmpty() && !usernameToRemove.isEmpty()) {
                User userToRemove = loginInstance.findUser(usernameToRemove);
                if (userToRemove != null) {
                    boolean removed = loginInstance.removeUserFromGroup(groupName, userToRemove);
                    if (removed) {
                        System.out.println("User removed from group successfully.");
                    } else {
                        System.out.println("Failed to remove user from group.");
                    }
                } else {
                    System.out.println("User not found.");
                }
            } else {
                System.out.println("Please enter both group name and username.");
            }
        });

        // Event handler for listing group members
        listGroupMembersButton.setOnAction(e -> {
            String groupName = groupNameField.getText();
            if (!groupName.isEmpty()) {
                Group group = loginInstance.getGroup(groupName);
                if (group != null) {
                    System.out.println("Members of group '" + groupName + "':");
                    List<User> members = new ArrayList<>();
                    members.addAll(group.getAdmins());
                    members.addAll(group.getInstructors());
                    members.addAll(group.getStudents());
                    for (User member : members) {
                        System.out.println("Username: " + member.getUsername() + ", Role: " + member.getRole());
                    }
                } else {
                    System.out.println("Group not found.");
                }
            } else {
                System.out.println("Please enter a group name.");
            }
        });

        // Article Management Components
        Label articleManagementLabel = new Label("Article Management:");
        TextField articleTitleField = new TextField();
        articleTitleField.setPromptText("Article Title");

        TextField articleDescriptionField = new TextField();
        articleDescriptionField.setPromptText("Article Description");

        TextField articleKeywordsField = new TextField();
        articleKeywordsField.setPromptText("Keywords (comma-separated)");

        TextField articleGroupsField = new TextField();
        articleGroupsField.setPromptText("Groups (comma-separated)");

        TextField articleLevelField = new TextField();
        articleLevelField.setPromptText("Level (Beginner, Intermediate, Advanced, Expert)");

        Button createArticleButton = new Button("Create Article");
        Button deleteArticleButton = new Button("Delete Article");
        Button listArticlesButton = new Button("List Articles");

        // Map to keep track of articles
        Map<Long, User.HelpArticle> articleMap = new HashMap<>();

        // Event handler for creating an article
        createArticleButton.setOnAction(e -> {
            String title = articleTitleField.getText();
            String description = articleDescriptionField.getText();
            List<String> keywords = Arrays.asList(articleKeywordsField.getText().split(","));
            List<String> groups = Arrays.asList(articleGroupsField.getText().split(","));
            String level = articleLevelField.getText();

            if (!title.isEmpty()) {
                User.HelpArticle newArticle = new User.HelpArticle(
                        System.currentTimeMillis(),
                        title,
                        description,
                        keywords,
                        "", // Empty body, as admin cannot edit or view body
                        new ArrayList<>(),
                        groups,
                        level,
                        currentUser.getUsername()
                );
                currentUser.addHelpArticle(newArticle);
                articleMap.put(newArticle.getId(), newArticle);
                System.out.println("Article created successfully.");
            } else {
                System.out.println("Please enter an article title.");
            }
        });

        // Event handler for deleting an article
        deleteArticleButton.setOnAction(e -> {
            String title = articleTitleField.getText();
            if (!title.isEmpty()) {
                boolean found = false;
                for (User userItem : loginInstance.listUsers()) {
                    for (User.HelpArticle article : userItem.getAllHelpArticles()) {
                        if (article.getTitle().equals(title)) {
                            userItem.removeHelpArticle(article.getId());
                            articleMap.remove(article.getId());
                            System.out.println("Article deleted successfully.");
                            found = true;
                            break;
                        }
                    }
                    if (found) break;
                }
                if (!found) {
                    System.out.println("Article not found.");
                }
            } else {
                System.out.println("Please enter an article title.");
            }
        });

        // Event handler for listing all articles
        listArticlesButton.setOnAction(e -> {
            System.out.println("Listing all articles:");
            articleMap.clear();
            for (User userItem : loginInstance.listUsers()) {
                for (User.HelpArticle article : userItem.getAllHelpArticles()) {
                    System.out.println("Title: " + article.getTitle() + ", Author: " + article.getAuthor());
                    articleMap.put(article.getId(), article);
                }
            }
        });

        // Backup and Restore Buttons
        Button backupButton = new Button("Backup Articles");
        Button restoreButton = new Button("Restore Articles");

        backupButton.setOnAction(e -> backupArticles());
        restoreButton.setOnAction(e -> restoreArticles());

        // View Messages and Search History
        Label messagesLabel = new Label("Messages from Users:");
        TextArea messagesArea = new TextArea();
        messagesArea.setEditable(false);
        messagesArea.setPrefRowCount(5);

        Button refreshMessagesButton = new Button("Refresh Messages");

        refreshMessagesButton.setOnAction(e -> {
            messagesArea.clear();
            List<Login.Message> messages = loginInstance.getMessages();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            for (Login.Message message : messages) {
                messagesArea.appendText("[" + message.getTimestamp().format(formatter) + "] "
                        + message.getUsername() + ": " + message.getContent() + "\n");
            }
        });

        Label searchHistoryLabel = new Label("User Search History:");
        TextArea searchHistoryArea = new TextArea();
        searchHistoryArea.setEditable(false);
        searchHistoryArea.setPrefRowCount(5);

        Button refreshSearchHistoryButton = new Button("Refresh Search History");

        refreshSearchHistoryButton.setOnAction(e -> {
            searchHistoryArea.clear();
            List<Login.SearchQuery> searchQueries = loginInstance.getSearchQueries();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            for (Login.SearchQuery query : searchQueries) {
                searchHistoryArea.appendText("[" + query.getTimestamp().format(formatter) + "] "
                        + query.getUsername() + " searched: " + query.getQuery() + "\n");
            }
        });

        // Logout button
        Button logoutButton = new Button("Logout");
        logoutButton.setOnAction(e -> {
            System.out.println("Logging out.");
            showLoginScreen(); // Return to login screen
        });

        // Add components to the layout
        vbox.getChildren().addAll(
                new Label("Admin Dashboard"),
                new Separator(),
                userManagementLabel,
                usernameField,
                passwordField,
                roleComboBox,
                new HBox(10, addUserButton, deleteUserButton, listUsersButton),
                UserLabel, UserArea,
                new Separator(),
                groupManagementLabel,
                groupNameField,
                specialAccessCheckBox,
                new HBox(10, createGroupButton, deleteGroupButton, listGroupsButton),
                GroupsLabel, GroupsArea,
                new Separator(),
                groupMembershipLabel,
                new HBox(10, addUserToGroupButton, removeUserFromGroupButton, listGroupMembersButton),
                new Separator(),
                articleManagementLabel,
                articleTitleField,
                articleDescriptionField,
                articleKeywordsField,
                articleGroupsField,
                articleLevelField,
                new HBox(10, createArticleButton, deleteArticleButton, listArticlesButton),
                new Separator(),
                new Label("Backup and Restore Articles:"),
                new HBox(10, backupButton, restoreButton),
                new Separator(),
                messagesLabel,
                messagesArea,
                refreshMessagesButton,
                new Separator(),
                searchHistoryLabel,
                searchHistoryArea,
                refreshSearchHistoryButton,
                new Separator(),
                logoutButton);

        // Wrap the VBox in a ScrollPane
        ScrollPane scrollPane = new ScrollPane(vbox);
        scrollPane.setFitToWidth(true); // Ensure the scroll pane fits the width of the content

        // Set the scene with the scroll pane
        Scene adminScene = new Scene(scrollPane, 800, 600); // Adjusted window height to 600
        window.setScene(adminScene);
        window.show();

        // Auto-refresh messages and search history when the dashboard is opened
        refreshMessagesButton.fire();
        refreshSearchHistoryButton.fire();
    }

    public static void main(String[] args) {
        launch(args); // Launch the JavaFX application
    }
}
