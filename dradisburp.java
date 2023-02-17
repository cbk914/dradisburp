import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;

public class DradisExtender implements IBurpExtender {
    
    private IBurpExtenderCallbacks callbacks;
    private String apiKey;
    private String apiUrl;
    private String searchParam1;
    private String searchParam2;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        
        // Create the user interface
        JFrame frame = new JFrame("Dradis Extension");
        JButton settingsButton = new JButton("Settings");
        JButton searchButton = new JButton("Search");
        frame.getContentPane().add(settingsButton);
        frame.getContentPane().add(searchButton);
        
        // Add an ActionListener to the settings button
        settingsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Show a dialog where the user can enter their API key and URL
                JTextField apiKeyField = new JTextField(apiKey);
                JTextField apiUrlField = new JTextField(apiUrl);
                JTextField searchParam1Field = new JTextField(searchParam1);
                JTextField searchParam2Field = new JTextField(searchParam2);
                Object[] message = {
                        "API Key:", apiKeyField,
                        "API URL:", apiUrlField,
                        "Search Param 1:", searchParam1Field,
                        "Search Param 2:", searchParam2Field
                };
                int result = JOptionPane.showConfirmDialog(frame, message, "Settings", JOptionPane.OK_CANCEL_OPTION);
                if (result == JOptionPane.OK_OPTION) {
                    apiKey = apiKeyField.getText();
                    apiUrl = apiUrlField.getText();
                    searchParam1 = searchParam1Field.getText();
                    searchParam2 = searchParam2Field.getText();
                }
            }
        });
        
        // Add an ActionListener to the search button
        searchButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Connect to the Dradis API
                String searchUrl = apiUrl + "/search?param1=" + searchParam1 + "&param2=" + searchParam2;
                byte[] searchRequest = callbacks.getHelpers().buildHttpRequest(callbacks.getHelpers().analyzeRequest(callbacks.getInvocation().getRequest()).getUrl());
                IHttpRequestResponse searchResponse = callbacks.makeHttpRequest(searchRequest, searchUrl);
                
                // Check if the response contains an issue library
                if (searchResponse.getResponse() != null && callbacks.getHelpers().analyzeResponse(searchResponse.getResponse()).getHeaders().contains("X-Dradis-Plugin: library")) {
                    byte[] libraryRequest = callbacks.getHelpers().buildHttpRequest(callbacks.getHelpers().analyzeRequest(callbacks.getInvocation().getRequest()).getUrl());
                    IHttpRequestResponse libraryResponse = callbacks.makeHttpRequest(libraryRequest, apiUrl + "/library");
                    
                    // Add a button for creating new issues in the library
                    JButton newIssueButton = new JButton("New Issue");
                    frame.getContentPane().add(newIssueButton);
                    
                    // Add an ActionListener to the new issue button
                    newIssueButton.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            // Show a dialog where the user can enter the details of the new issue
                            JTextField issueTitleField = new JTextField();
                            JTextField issueDescriptionField = new JTextField();
                            Object[] message = {
                                    "Issue Title:", issueTitleField,
                                    "Issue Description:", issueDescriptionField
                            };
                            int result = JOptionPane.showConfirmDialog(frame, message, "New Issue", JOptionPane.OK_CANCEL_OPTION);
                            if (result == JOptionPane.OK_OPTION) {
                                // Create the new issue in the library
                                String newIssueUrl = apiUrl + "/library/issues";
                                String issueTitle = issueTitleField.getText();
                                String issueDescription = issueDescriptionField.getText();
                                String newIssueData = "title=" + issueTitle + "&description=" + issueDescription;
                                byte[] newIssueRequest = callbacks.getHelpers().buildHttpMessage(newIssueUrl, "POST", newIssueData.getBytes());
                                IHttpRequestResponse newIssueResponse = callbacks.makeHttpRequest(callbacks.getInvocation().getToolFlag(), newIssueRequest);
                                
                                // Show a message to the user indicating whether the new issue was created successfully or not
                                if (newIssueResponse.getResponse() != null && callbacks.getHelpers().analyzeResponse(newIssueResponse.getResponse()).getStatusCode() == 201) {
                                    JOptionPane.showMessageDialog(frame, "New issue created successfully", "Success", JOptionPane.INFORMATION_MESSAGE);
                                } else {
                                    JOptionPane.showMessageDialog(frame, "Failed to create new issue", "Error", JOptionPane.ERROR_MESSAGE);
                                }
                            }
                        }
                    });
                }
            }
        });
        
        // Show the user interface
        frame.pack();
        frame.setVisible(true);
    }
    
}
