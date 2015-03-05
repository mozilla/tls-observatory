package amqpmodule

import (
	"log"

	"github.com/streadway/amqp"
)

type broker struct {
	ConnectionURL string
	channel       *amqp.Channel
	Queues        []string
}

var bro broker

func init() {
	bro = broker{}
}

func Publish(qname string, data []byte) error {

	if !bro.isQueueDeclared(qname) {

		err := bro.declareQueue(qname)

		if err != nil {
			return err
		}
	}

	err := bro.channel.Publish(
		"",    // exchange
		qname, // routing key
		false, // mandatory
		false,
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "text/plain",
			Body:         data,
		})

	return err

}

func Consume(qname string) (<-chan []byte, error) {

	if !bro.isQueueDeclared(qname) {

		err := bro.declareQueue(qname)

		if err != nil {
			return nil, err
		}
	}

	msgs, err := bro.channel.Consume(
		qname, // queue
		"",    // consumer
		false, // auto-ack
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,   // args
	)

	if err != nil {
		return nil, err
	}

	msgChan := make(chan []byte)

	go func(c chan []byte, m <-chan amqp.Delivery) {

		for d := range m {
			c <- d.Body
			err = d.Ack(false)
			if err != nil {
				log.Fatal("Failed to ack amqp delivery")
			}
		}

	}(msgChan, msgs)

	return msgChan, nil
}

func RegisterURL(URL string) error {

	bro.ConnectionURL = URL

	conn, err := amqp.Dial(URL)
	if err != nil {
		conn.Close()
		return err
	}

	ch, err := conn.Channel()
	if err != nil {
		ch.Close()
		return err
	}

	err = ch.Qos(
		1,     // prefetch count
		0,     // prefetch size
		false, // global
	)

	if err != nil {
		ch.Close()
		return err
	}

	bro.channel = ch

	return nil
}

func (b broker) declareQueue(qname string) error {

	_, err := b.channel.QueueDeclare(
		qname, // name
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)

	if err != nil {
		return err
	} else {
		b.Queues = append(b.Queues, qname)
		return nil
	}
}

func (b broker) isQueueDeclared(qname string) bool {
	for i := 0; i < len(b.Queues); i++ {
		if qname == b.Queues[i] {
			return true
		}
	}

	return false
}
