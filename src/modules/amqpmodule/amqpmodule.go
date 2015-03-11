package amqpmodule

import (
	"log"

	"github.com/streadway/amqp"
)

type Broker struct {
	ConnectionURL string
	channel       *amqp.Channel
	Queues        []string
}

func (b *Broker) Publish(qname string, data []byte) error {
	log.Println(b.isQueueDeclared(qname))

	if !b.isQueueDeclared(qname) {

		err := b.declareQueue(qname)

		if err != nil {
			return err
		}
	}

	err := b.channel.Publish(
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

func (b *Broker) Consume(qname string) (<-chan []byte, error) {

	log.Println(b.isQueueDeclared(qname))
	if !b.isQueueDeclared(qname) {

		err := b.declareQueue(qname)

		if err != nil {
			return nil, err
		}
	}

	msgs, err := b.channel.Consume(
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

func RegisterURL(URL string) (*Broker, error) {

	b := &Broker{}

	b.ConnectionURL = URL

	conn, err := amqp.Dial(URL)
	if err != nil {
		conn.Close()
		return b, err
	}

	ch, err := conn.Channel()
	if err != nil {
		ch.Close()
		return b, err
	}

	err = ch.Qos(
		1,     // prefetch count
		0,     // prefetch size
		false, // global
	)

	if err != nil {
		ch.Close()
		return b, err
	}

	b.channel = ch

	return b, nil
}

func (b *Broker) declareQueue(qname string) error {

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

func (b *Broker) isQueueDeclared(qname string) bool {
	log.Println(b.Queues)
	for i := 0; i < len(b.Queues); i++ {
		if qname == b.Queues[i] {
			return true
		}
	}

	return false
}
