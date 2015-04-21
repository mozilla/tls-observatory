package amqpmodule

import (
	"log"

	"github.com/streadway/amqp"
)

const defExchange = "amq.direct"

type Broker struct {
	connectionURL string
	channel       *amqp.Channel
	queues        map[string]string
}

func (b *Broker) Publish(qname, routKey string, data []byte) error {

	if _, ok := b.queues[routKey]; !ok {

		_, err := b.declareQueue(qname, routKey)

		if err != nil {
			return err
		}
	}

	err := b.channel.Publish(
		defExchange, // exchange
		routKey,     // routing key
		false,       // mandatory
		false,
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "text/plain",
			Body:         data,
		})

	return err

}

func (b *Broker) Consume(qname, routKey string) (<-chan []byte, error) {

	ok := false
	err := error(nil)

	if _, ok = b.queues[routKey]; !ok {

		_, err = b.declareQueue(qname, routKey)

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

	b.queues = make(map[string]string)

	b.connectionURL = URL

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

func (b *Broker) declareQueue(qname, routKey string) (string, error) {

	q, err := b.channel.QueueDeclare(
		qname, // name
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)

	if err != nil {
		return "", err
	} else {

		err = b.channel.QueueBind(q.Name, routKey, defExchange, false, nil)
		if err != nil {
			return "", err
		}
		b.queues[routKey] = qname
		return q.Name, nil
	}
}
