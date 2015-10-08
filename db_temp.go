package main

import (
	//"database/sql"
	"fmt"
	"github.com/lib/pq"
	"strconv"
	"sync"
	"time"
)

func main() {

	//	url := fmt.Sprintf("postgres://postgres:pass@172.17.42.1:5432/postgres?sslmode=disable")

	//	db, err := sql.Open("postgres", url)

	//	if err != nil {
	//		fmt.Println(err)
	//	}

	var err error

	reportProblem := func(ev pq.ListenerEventType, err error) {
		if err != nil {
			fmt.Println(err.Error())
		}
	}
	var wg sync.WaitGroup

	for i := 1; i <= 10; i++ {

		go func(name string) {

			wg.Add(1)
			defer wg.Done()
			l := pq.NewListener("postgres://postgres:pass@172.17.42.1:5432/postgres?sslmode=disable", 10*time.Second, time.Minute, reportProblem)

			err = l.Listen("watchers")
			if err != nil {
				panic(err)
			}
			var n *pq.Notification

			for {
				n = <-l.Notify
				fmt.Println("Listener ", name, " Received Notification: ", n.Extra)
			}
		}(strconv.Itoa(i))
	}

	time.Sleep(10 * time.Second)

	wg.Wait()

}
