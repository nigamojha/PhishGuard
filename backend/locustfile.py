# locustfile.py
from locust import HttpUser, task, between

class PhishGuardUser(HttpUser):
    # Each simulated user will wait 1 to 3 seconds between tasks
    wait_time = between(1, 3)
    
    # This is the task the user will perform repeatedly
    @task
    def analyze_url(self):
        # A sample phishing URL to test the endpoint with
        test_url = "http://hsbc.co.uk.secure-login-attempt.com/myaccount/password/"
        
        headers = {'Content-Type': 'application/json'}
        
        # We use self.client to send a POST request to the /analyze endpoint
        # The host part (e.g., https://phishguard-api.onrender.com) is provided when we run Locust
        self.client.post("/analyze", json={"url": test_url}, headers=headers)