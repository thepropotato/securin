# NVD CVE API setup

The database file is deleted due to size constraints on github. So follow the setup procedure to see the work.

1. Clone the repository
2. Run the `database.py` file first. This creates a SQLite database file with the name `cve_data.db`
3. Run the `cron-job.py` file. This copies all the API responses into the created database.
4. Then run the `server.py` file to start the server.
5. Now open the `index.html` file to see the UI. 

That's it for the setup process. With all of this steps performed correctly, you will be able to run the app correctly.

# Key Decisions

1. The API is fetched with 2000 rows per request, iteratively (in small chunks).
2. A small delay of 5 seconds is introduced between each API call, to avoid rate limits.
3. A single table for all the required features is created to avoid data redundancy.

For any details/clarifications, please contact me.
Mail : notvenupulagam@gmail.com