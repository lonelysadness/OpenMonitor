package nfq

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/hashicorp/go-multierror"
)

var (
	// IPv4 chains
	v4chains = []string{
		"mangle OPENMONITOR-INGEST-OUTPUT",
		"mangle OPENMONITOR-INGEST-INPUT",
		"filter OPENMONITOR-FILTER",
	}

	// IPv6 chains
	v6chains = []string{
		"mangle OPENMONITOR-INGEST-OUTPUT",
		"mangle OPENMONITOR-INGEST-INPUT",
		"filter OPENMONITOR-FILTER",
	}

	// IPv4 rules
	v4rules = []string{
		// Mangle rules
		"mangle OPENMONITOR-INGEST-OUTPUT -j CONNMARK --restore-mark",
		"mangle OPENMONITOR-INGEST-OUTPUT -m mark --mark 0 -j NFQUEUE --queue-num 17040 --queue-bypass",

		"mangle OPENMONITOR-INGEST-INPUT -j CONNMARK --restore-mark",
		"mangle OPENMONITOR-INGEST-INPUT -m mark --mark 0 -j NFQUEUE --queue-num 17041 --queue-bypass",

		// Filter rules (order is important)
		"filter OPENMONITOR-FILTER -m mark --mark 0 -j DROP",
		
		// Handle ICMP first
		"filter OPENMONITOR-FILTER -p icmp -m mark --mark 1701 -j RETURN",
		"filter OPENMONITOR-FILTER -p icmpv6 -m mark --mark 1701 -j RETURN",
		
		// Always rules
		"filter OPENMONITOR-FILTER -m mark --mark 1710 -j RETURN",
		"filter OPENMONITOR-FILTER -m mark --mark 1711 -p icmp -j RETURN",
		"filter OPENMONITOR-FILTER -m mark --mark 1711 -p icmpv6 -j RETURN",
		"filter OPENMONITOR-FILTER -m mark --mark 1711 -j REJECT --reject-with icmp-admin-prohibited",
		"filter OPENMONITOR-FILTER -m mark --mark 1712 -j DROP",

		// Regular rules
		"filter OPENMONITOR-FILTER -m mark --mark 1700 -j RETURN",
		"filter OPENMONITOR-FILTER -m mark --mark 1701 -j REJECT --reject-with icmp-admin-prohibited",
		"filter OPENMONITOR-FILTER -m mark --mark 1702 -j DROP",
		
		// Save connection mark after processing
		"filter OPENMONITOR-FILTER -j CONNMARK --save-mark",

		// Protocol specific rules
		"filter OPENMONITOR-FILTER -p igmp -j ACCEPT",

		// Filter rules that handle marks
		"filter OPENMONITOR-FILTER -m mark --mark 0 -j DROP",
		"filter OPENMONITOR-FILTER -m mark --mark 1700 -j RETURN",      // Accept
		"filter OPENMONITOR-FILTER -m mark --mark 1701 -j REJECT",      // Block
		"filter OPENMONITOR-FILTER -m mark --mark 1702 -j DROP",        // Drop
		"filter OPENMONITOR-FILTER -m mark --mark 1710 -j RETURN",      // Accept Always
		"filter OPENMONITOR-FILTER -m mark --mark 1711 -j REJECT",      // Block Always
		"filter OPENMONITOR-FILTER -m mark --mark 1712 -j DROP",        // Drop Always
	}

	// IPv6 rules
	v6rules = []string{
		// Mangle rules
		"mangle OPENMONITOR-INGEST-OUTPUT -j CONNMARK --restore-mark",
		"mangle OPENMONITOR-INGEST-OUTPUT -m mark --mark 0 -j NFQUEUE --queue-num 17060 --queue-bypass",

		"mangle OPENMONITOR-INGEST-INPUT -j CONNMARK --restore-mark",
		"mangle OPENMONITOR-INGEST-INPUT -m mark --mark 0 -j NFQUEUE --queue-num 17160 --queue-bypass",

		// Filter rules
		"filter OPENMONITOR-FILTER -m mark --mark 0 -j DROP",
		"filter OPENMONITOR-FILTER -m mark --mark 1700 -j RETURN",
		"filter OPENMONITOR-FILTER -m mark --mark 1701 -p icmpv6 -j RETURN",
		"filter OPENMONITOR-FILTER -m mark --mark 1701 -j REJECT --reject-with icmp6-adm-prohibited",
		"filter OPENMONITOR-FILTER -m mark --mark 1702 -j DROP",
		"filter OPENMONITOR-FILTER -j CONNMARK --save-mark",
		"filter OPENMONITOR-FILTER -m mark --mark 1710 -j RETURN",
		"filter OPENMONITOR-FILTER -m mark --mark 1711 -p icmpv6 -j RETURN",
		"filter OPENMONITOR-FILTER -m mark --mark 1711 -j REJECT --reject-with icmp6-adm-prohibited",
		"filter OPENMONITOR-FILTER -m mark --mark 1712 -j DROP",

		// Add ICMPv6 specific rules
		"filter OPENMONITOR-FILTER -p icmpv6 -m mark --mark 1700 -j RETURN",
		"filter OPENMONITOR-FILTER -p icmpv6 -m mark --mark 1701 -j RETURN",
		"filter OPENMONITOR-FILTER -p icmpv6 -m mark --mark 1702 -j DROP",
		"filter OPENMONITOR-FILTER -p icmpv6 -m mark --mark 1710 -j RETURN",
		"filter OPENMONITOR-FILTER -p icmpv6 -m mark --mark 1711 -j RETURN",
		"filter OPENMONITOR-FILTER -p icmpv6 -m mark --mark 1712 -j DROP",
	}

	// IPv4 base rules
	v4once = []string{
			"mangle OUTPUT -j OPENMONITOR-INGEST-OUTPUT",
			"mangle INPUT -j OPENMONITOR-INGEST-INPUT", 
			"filter OUTPUT -j OPENMONITOR-FILTER",
			"filter INPUT -j OPENMONITOR-FILTER",
	}

	// IPv6 base rules
	v6once = []string{
		"mangle OUTPUT -j OPENMONITOR-INGEST-OUTPUT",
		"mangle INPUT -j OPENMONITOR-INGEST-INPUT",
		"filter OUTPUT -j OPENMONITOR-FILTER",
		"filter INPUT -j OPENMONITOR-FILTER",
	}
)

// Remove the init() function that was creating the unused file
// Remove all debug logging functionality

func flushIPTables() error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	// List of tables and default chains to flush
	tables := []string{"mangle", "filter"}
	defaultChains := []string{"INPUT", "OUTPUT", "FORWARD"}

	for _, table := range tables {
		// Flush default chains
		for _, chain := range defaultChains {
			if err := ipt.ClearChain(table, chain); err != nil {
				return fmt.Errorf("failed to clear chain %s in table %s: %w", chain, table, err)
			}
		}

		// List and flush custom chains
		chains, err := ipt.ListChains(table)
		if err != nil {
			return fmt.Errorf("failed to list chains in table %s: %w", table, err)
		}

		for _, chain := range chains {
			// Skip default chains
			if contains(defaultChains, chain) {
				continue
			}
			if err := ipt.ClearChain(table, chain); err != nil {
				return fmt.Errorf("failed to clear chain %s in table %s: %w", chain, table, err)
			}
			// Try to delete custom chains
			if err := ipt.DeleteChain(table, chain); err != nil {
				// Ignore errors here as chain might be in use
				fmt.Printf("Warning: could not delete chain %s in table %s: %v\n", chain, table, err)
			}
		}
	}
	return nil
}

// Helper function to check if a string is in a slice
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func StartNFQueue() error {
	if err := activateIPTables(); err != nil {
		return fmt.Errorf("failed to activate iptables: %w", err)
	}
	return nil
}

func StopNFQueue() error {
	if err := deactivateIPTables(); err != nil {
		return fmt.Errorf("failed to deactivate iptables: %w", err)
	}
	return nil
}

func activateIPTables() error {
	if err := flushIPTables(); err != nil {
		return err
	}

	if err := setupChains(false); err != nil {
		return err
	}

	if err := setupChains(true); err != nil {
		return err
	}

	return nil
}

func setupChains(isV6 bool) error {
	protocol := iptables.ProtocolIPv4
	chains := v4chains
	rules := v4rules
	once := v4once

	if isV6 {
		protocol = iptables.ProtocolIPv6
		chains = v6chains
		rules = v6rules
		once = v6once
	}

	ipt, err := iptables.NewWithProtocol(protocol)
	if err != nil {
		return err
	}

	// First create all chains
	for _, chain := range chains {
		parts := strings.Split(chain, " ")
		// Create the chain first
		if err := ipt.NewChain(parts[0], parts[1]); err != nil {
			// Ignore if chain already exists
			if !strings.Contains(err.Error(), "Chain already exists") {
				return fmt.Errorf("failed to create chain %s: %w", chain, err)
			}
		}
		// Then clear it
		if err := ipt.ClearChain(parts[0], parts[1]); err != nil {
			return fmt.Errorf("failed to clear chain %s: %w", chain, err)
		}
	}

	// Set default policies
	if err := ipt.Append("filter", "INPUT", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := ipt.Append("filter", "OUTPUT", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Then add all rules
	for _, rule := range rules {
		parts := strings.Split(rule, " ")
		if err := ipt.Append(parts[0], parts[1], parts[2:]...); err != nil {
			return fmt.Errorf("failed to append rule %s: %w", rule, err)
		}
	}

	// Finally add base rules
	for _, rule := range once {
		parts := strings.Split(rule, " ")
		exists, err := ipt.Exists(parts[0], parts[1], parts[2:]...)
		if err != nil {
			return err
		}
		if !exists {
			if err := ipt.Insert(parts[0], parts[1], 1, parts[2:]...); err != nil {
				return fmt.Errorf("failed to insert rule %s: %w", rule, err)
			}
		}
	}

	return nil
}

func deactivateIPTables() error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	var result *multierror.Error

	// Remove base rules
	for _, rule := range v4once {
		parts := strings.Split(rule, " ")
		if err := ipt.Delete(parts[0], parts[1], parts[2:]...); err != nil {
			result = multierror.Append(result, err)
		}
	}

	// Remove chains
	for _, chain := range v4chains {
		parts := strings.Split(chain, " ")
		if err := ipt.ClearChain(parts[0], parts[1]); err != nil {
			result = multierror.Append(result, err)
		}
		if err := ipt.DeleteChain(parts[0], parts[1]); err != nil {
			result = multierror.Append(result, err)
		}
	}

	ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return err
	}

	// Remove base rules for IPv6
	for _, rule := range v6once {
		parts := strings.Split(rule, " ")
		if err := ipt.Delete(parts[0], parts[1], parts[2:]...); err != nil {
			result = multierror.Append(result, err)
		}
	}

	// Remove chains for IPv6
	for _, chain := range v6chains {
		parts := strings.Split(chain, " ")
		if err := ipt.ClearChain(parts[0], parts[1]); err != nil {
			result = multierror.Append(result, err)
		}
		if err := ipt.DeleteChain(parts[0], parts[1]); err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result.ErrorOrNil()
}
