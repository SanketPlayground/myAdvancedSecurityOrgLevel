
Code-scanning issues and dependencies (including license) information is available within the repo API in github. This action is written to demonstrate the use of xlsx package and github api to generate a fast excel report (alerts.xlsx) using this API.  

If you would like to explore the these APIs using postman, plese see the [postman collection](Reports%20Postman%20Collection/) folder for details. 


![Screenshot 2021-12-20 at 12 32 22 AM](https://user-images.githubusercontent.com/23517709/146687440-20259d95-3a6a-4d03-8cf0-4fb401414b41.png)

#### dependencies-list sheet
<img width="863" alt="Screenshot 2021-12-20 at 12 26 16 AM" src="https://user-images.githubusercontent.com/23517709/146687357-062d7710-d33a-4987-9974-0c0c3a364602.png">

#### code-scanning-issues sheet
<img width="717" alt="Screenshot 2021-12-20 at 12 26 38 AM" src="https://user-images.githubusercontent.com/23517709/146687360-b04a651f-6e06-4b40-8b0a-d436e50c68b4.png">

#### dependencies-license sheet
![image](https://user-images.githubusercontent.com/23517709/147328752-73398082-421b-4429-b7cb-0059eeab3abb.png)

#### code-scanning-pivot sheet
![image](https://user-images.githubusercontent.com/23517709/152539730-72f7c44a-43f5-44f4-b3be-35d002f31dd8.png)

#### secret-scanning-alerts sheet
![image](https://user-images.githubusercontent.com/23517709/151943026-5153f538-7ce0-4cda-a6f0-cbe638876925.png)

#### software-composition-analysis sheet
![image](https://user-images.githubusercontent.com/23517709/152521657-4c2ab1f2-0d85-45b4-bdb9-feacf6befc91.png)


## Using to the Action

The action require a github personal access token passed in the workflow file. The correct way to do this is to use repository secrets.

The action creates alert.xlsx file in the workspace, which needs to be uploaded using the upload-artifact action.

      # Generate issues and save results
      - uses: amitgupta7/ghas-reports-action@v3.5
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          # optionally define repo (default is calling repo)
          # repo: 'dsp-testing/ghas-intro-6'

      - uses: actions/upload-artifact@v3.0.0
        with:
          name: results
          path: alerts.xlsx          

## Code in Main

> First, you'll need to have a reasonably modern version of `node` handy. This won't work with versions older than 9, for instance.

Install the dependencies  
```bash
$ npm install
```

Build the typescript and package it for distribution
```bash
$ npm run build && npm run package
```

Run the tests by setting the INPUT_TOKEN and GITHUB_REPOSITORY environment variables. This should create an [alerts.xlsx report file](alerts.xlsx) in the project root. 

```bash
$ export INPUT_TOKEN=ghp_GITHUB_TOKEN_HERE
$ export GITHUB_REPOSITORY=amitgupta7/WebGoat
$ npm test

> typescript-action@0.0.0 test
> jest

  console.log
    ::error::No login found, using GITHUB_REPOSITORY
    ::debug::CodeQL[293]:       open       java/random-used-once       warning
    ::debug::CodeQL[292]:       open       java/potentially-weak-cryptographic-algorithm       warning
    ::debug::CodeQL[291]:       open       java/unsafe-get-resource       warning
    ::debug::CodeQL[5]:       open       js/html-constructed-from-input       error
    ::debug::CodeQL[4]:       open       js/html-constructed-from-input       error
    ::debug::CodeQL[3]:       open       js/xss-through-dom       warning
    ::debug::CodeQL[2]:       open       js/incomplete-sanitization       warning
    ::debug::CodeQL[1]:       open       js/incomplete-sanitization       warning

      at Object.<anonymous> (__tests__/main.test.ts:13:11)

 PASS  __tests__/main.test.ts (6.968 s)
  ✓ test runs (6132 ms)

Test Suites: 1 passed, 1 total
Tests:       1 passed, 1 total
Snapshots:   0 total
Time:        7.04 s
Ran all test suites.
```

## Publish to a distribution branch

Actions are run from Public GitHub repos so we will checkin the packed dist folder. 

Then run [ncc](https://github.com/zeit/ncc) and push the results:
```bash
$ npm run package
$ git add dist
$ git commit -a -m "prod dependencies"
$ git push origin releases/v1
```

Note: We recommend using the `--license` option for ncc, which will create a license file for all of the production node modules used in your project.

Your action is now published! :rocket: 

See the [versioning documentation](https://github.com/actions/toolkit/blob/master/docs/action-versioning.md)
