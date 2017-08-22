WARNING: It's possible for these files to become out of date, as we don't expect contributors to check these files still work with the changes they make to the code.

# Running with Kubernetes

You can run the TLS Observatory API and Scanner, in addition to PostgreSQL, in a Kubernetes cluster. For example, you might want to use [minikube](https://github.com/kubernetes/minikube) to run a Kubernetes cluster locally in which you can run everything you need to run TLS Observatory.

This configuration uses the mozilla/tls-observatory image. By default, Kubernetes will pull this image from Dockerhub.

Ensure `kubectl` is correctly configured and has access to your cluster, and then run `kubectl apply -f deployment.yaml` in order to create the PostgreSQL database, the API, and the scanner. The database will be uninitialized, so once the PostgreSQL container is running (check the status with `kubectl get po`), you can run the setup_db job with `kubectl apply -f setup_db.yaml` to initialize the database. After the job is finished, the api and scanner containers should successfully start and be ready for connections. You can then get the URL for the API with `kubectl describe svc api`. If you're using `minikube`, you need to instead run `minikube service api --url`. For example:

```
❯ minikube service api --url     
http://192.168.64.6:30647

❯ tlsobs -observatory http://192.168.64.6:30647 -r mozilla.com 
# output omitted
```
