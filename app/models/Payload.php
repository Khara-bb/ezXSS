<?php

class Payload_model extends Model
{
    /**
     * Summary of table
     * 
     * @var string
     */
    public $table = 'payloads';

    /**
     * Get all payloads
     * 
     * @return array
     */
    public function getAll()
    {
        $database = Database::openConnection();
        $database->getAll($this->table);

        $data = $database->fetchAll();

        return $data;
    }

    /**
     * Get all payloads from user by user id
     * 
     * @param int $id The user id
     * @throws Exception
     * @return array
     */
    public function getAllByUserId($id)
    {
        $database = Database::openConnection();
        $database->prepare("SELECT * FROM $this->table WHERE `user_id` = :user_id ORDER BY `id` ASC");
        $database->bindValue(':user_id', $id);

        if (!$database->execute()) {
            throw new Exception('Something unexpected went wrong');
        }

        $data = $database->fetchAll();

        return $data;
    }

    /**
     * Add payload
     * 
     * @param int $userId The user id
     * @param string $payload The payload url
     * @param string $whitelist The allowed domain (optional)
     * @throws Exception
     * @return string The inserted payload ID
     */
    public function add($userId, $payload, $whitelist = '')
    {
        $database = Database::openConnection();

        $database->prepare("INSERT INTO $this->table (`payload`, `user_id`, `whitelist`) VALUES (:payload, :user_id, :whitelist);");
        $database->bindValue(':payload', $payload);
        $database->bindValue(':user_id', $userId);
        $database->bindValue(':whitelist', $whitelist);

        if (!$database->execute()) {
            throw new Exception('Something unexpected went wrong');
        }

        return $database->lastInsertId();
    }

    /**
     * Get payload by payload url
     * 
     * @param mixed $payload The payload url
     * @throws Exception
     * @return mixed
     */
    public function getByPayload($payload)
    {
        $database = Database::openConnection();
        $database->prepare("SELECT * FROM $this->table WHERE `payload` = :payload ORDER BY `id` ASC LIMIT 1");
        $database->bindValue(':payload', $payload);
        $database->execute();

        if ($database->countRows() === 0) {
            throw new Exception('Payload not found');
        }

        $payload = $database->fetch();

        return $payload;
    }

    /**
     * Check if payload domain is available
     * 
     * @param mixed $payload The payload url
     * @throws Exception
     * @return mixed
     */
    public function isAvailable($payload)
    {
        $database = Database::openConnection();
        $database->prepare("SELECT * FROM $this->table WHERE `payload` = :payload ORDER BY `id` ASC LIMIT 1");
        $database->bindValue(':payload', $payload);
        $database->execute();

        if ($database->countRows() === 0) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Check if domain conflicts with existing payloads
     * 
     * @param mixed $payload The payload url to check
     * @param int $userId The user ID to check ownership for
     * @param string $whitelist The allowed domain to check for conflicts
     * @throws Exception
     * @return mixed
     */
    public function isDomainAvailable($payload, $userId, $whitelist = '')
    {
        $database = Database::openConnection();
        
        $database->getAll($this->table);
        $payloads = $database->fetchAll();
        
        $payloadParts = explode('/', $payload, 2);
        $newDomain = $payloadParts[0];
        $newPath = isset($payloadParts[1]) ? $payloadParts[1] : '';

        foreach ($payloads as $existing) {
            $existingParts = explode('/', $existing['payload'], 2);
            $existingDomain = $existingParts[0];
            $existingPath = isset($existingParts[1]) ? $existingParts[1] : '';

            // Allow same payload for same user IF whitelists are different
            if ($existing['user_id'] == $userId && ($payload === $existing['payload'] || $newDomain === $existingDomain  )) {
                $currentWhitelist = strtolower(trim($whitelist));
                $existingWhitelist = strtolower(trim($existing['whitelist'] ?? ''));

                // If both have empty whitelists, it's a conflict
                if (empty($currentWhitelist) && empty($existingWhitelist)) {
                    return false;
                }
                
                // If whitelists are different, it's allowed (dispatching mode)
                if ($currentWhitelist !== $existingWhitelist) {
                    continue;
                }
                
                // If whitelists are identical, it's a conflict
                return false;
            }

            
            if ($payload === $existing['payload'] ||
                ($newDomain === $existingDomain && (
                    $existing['user_id'] != $userId ||
                    $newPath === $existingPath ||
                    (empty($newPath) && !empty($existingPath))
                ))
            ) {
                return false;
            }
        }
        
        return true;
    }
}
